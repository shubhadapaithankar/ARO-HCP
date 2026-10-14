#!/usr/bin/env python3
"""Apply scoped PR 7371 review fixes against the reviewed source tree."""
from pathlib import Path
import io
import json
import re
from ruamel.yaml import YAML

ROOT = Path.cwd()
A = ROOT / 'observability/alerts/backup-slo-prometheusRule.yaml'
AT = A.with_name('backup-slo-prometheusRule_test.yaml')
R = ROOT / 'observability/recording-rules/backup-slo-recordingRule.yaml'
RT = R.with_name('backup-slo-recordingRule_test.yaml')
y = YAML(typ='safe')
y.default_flow_style = False
y.sort_base_mapping_type_on_output = False
y.width = 4096
old_a, old_r = A.read_text(), R.read_text()
a, r = old_a, old_r

def replace(text, before, after, count=1):
    actual = text.count(before)
    if actual != count:
        raise RuntimeError(f'Expected {count} instances, found {actual}: {before[:100]!r}')
    return text.replace(before, after)

assert a.count('summary:') == 12
lines = a.splitlines(True)
for i, line in enumerate(lines):
    if line.lstrip().startswith('summary:'):
        lines[i] = line.replace(' on {{ $labels.cluster }}', '')
a = ''.join(lines)
assert all('$labels.cluster' not in l for l in a.splitlines() if l.lstrip().startswith('summary:'))
a = replace(a, '  # Driven by the recording rules in recording-rules/backup-slo-recordingRule.yaml.\n',
    '  # Freshness, Errors and Latency read raw metrics; Traffic and proxy alerts\n'
    '  # also use recording-rules/backup-slo-recordingRule.yaml.\n'
    '  # Thresholds are proposed monitoring policy, pending SLI/SLO alignment\n'
    '  # in ARO-29948; passing these tests does not establish SLO approval.\n')
a = replace(a, '    # ticket\'s "correlationId per namespace (derived from schedule)" guidance.\n',
    '    # ticket\'s "correlationId per namespace (derived from schedule)" guidance.\n'
    '    # Changing the namespace portion of a schedule name creates a new\n'
    '    # hosted_cluster_namespace/alert identity. The old source series must\n'
    '    # stop being exported before it becomes stale; a cadence-only rename\n'
    '    # need not change the extracted namespace. Keep selectors/extraction\n'
    '    # in sync with backend/pkg/controllers/cluster/backups/schedule.go.\n'
    '    # PR #7227 changed production to 6-hourly. These 12h/24h/72h limits\n'
    '    # represent 2/4/12 production intervals, not hourly backup windows.\n'
    '    # TODO(ARO-29948): confirm these thresholds with the SLO owners; when\n'
    '    # cadence changes, update all three tiers, Traffic, and their tests.\n')
a = replace(a,
    '    # (e.g. the 10m pre-hook timeout in internal/backup/backup.go:88) because\n'
    '    # that 5m window\'s attempt-rate gate then reads zero. A full long/short\n'
    '    # window always contains both the attempt and any failure completing\n'
    '    # within the hook/snapshot timeouts, so neither issue applies here.\n',
    '    # when an attempt-based gate reads zero. A 5m confirmation window can\n'
    '    # still exclude an attempt that completes later; completed-outcome\n'
    '    # counters below remove that numerator/denominator timing mismatch.\n')
hook_lines = (ROOT / 'internal/backup/backup.go').read_text().splitlines()
hook_line = next(i for i,l in enumerate(hook_lines, 1) if 'Timeout: metav1.Duration{Duration: 10 * time.Minute}' in l)
a = replace(a, '    # contribution even when a sibling counter is absent.\n',
    '    # contribution even when a sibling counter is absent.\n'
    f'    # Timeout source: internal/backup/backup.go:{hook_line}, etcdBackupHooks\n'
    '    # PreHooks.Exec.Timeout = 10 * time.Minute.\n'
    '    # Volume floors are attempt COUNTS over each long window, not rates\n'
    '    # per second. Deduplicate HA scrapes before summing absolute counts.\n')
for window, floor in [('1h',3),('6h',5),('3d',10)]:
    a = replace(a,
        f'        sum by (cluster) (increase(velero_backup_attempt_total[{window}])) >= {floor}',
        f'        sum by (cluster) (\n'
        f'          max without (prometheus_replica) (increase(velero_backup_attempt_total[{window}]))\n'
        f'        ) >= {floor}')
companion = '''    # A successful-timestamp series does not exist until the first success.
    # Compare observed production schedule statuses with success-series presence
    # per HC so a healthy sibling cannot hide a never-successful schedule.
    # The 12h hold is a continuous-observation grace period (two production
    # intervals), not the age of the HC or a fabricated timestamp of zero.
    # This also detects loss of a previously exported success series. Missing
    # schedules with no status at all remain outside this inventory; an
    # independent eligible-HC/Schedule inventory and pause state need ARO-29949.
    - alert: userJourneyBackupNeverSucceeded
      expr: |
        group by (cluster, hosted_cluster_namespace) (
          label_replace(
            velero_backup_last_status{schedule=~".+-6-hourly"},
            "hosted_cluster_namespace", "$1", "schedule", "(.+)-6-hourly"
          )
        )
        unless on (cluster, hosted_cluster_namespace)
        group by (cluster, hosted_cluster_namespace) (
          label_replace(
            velero_backup_last_successful_timestamp{schedule=~".+-6-hourly"},
            "hosted_cluster_namespace", "$1", "schedule", "(.+)-6-hourly"
          )
        )
      for: 12h
      labels:
        severity: "4"
        slo: backup-availability
      annotations:
        summary: "no successful backup timestamp for {{ $labels.hosted_cluster_namespace }} after 12h of observed schedule status"
        description: "HostedCluster namespace {{ $labels.hosted_cluster_namespace }} on management cluster {{ $labels.cluster }} has reported a 6-hourly schedule status without a successful backup timestamp for 12h. Check initial backup failures, metric resets, and schedule pause state. This signal requires an observed schedule status; it cannot detect a schedule that was never delivered."
        runbook_url: "https://github.com/Azure/ARO-HCP/blob/main/docs/backups.md"
        correlationId: "userJourneyBackupNeverSucceeded/{{ $labels.cluster }}/{{ $labels.hosted_cluster_namespace }}"
'''
a = replace(a, '  - name: arohcp_backup_slo_error_alerts\n', companion + '  - name: arohcp_backup_slo_error_alerts\n')
a = replace(a,
    '  # healthy. The 2h avg window is well within a single 6-hourly cycle, but\n'
    '  # the 1d baseline denominator smooths this out; `for: 1h` requires the\n'
    '  # collapse to persist before paging.\n',
    '  # healthy. A 12h observation window spans two production intervals; the\n'
    '  # 1d baseline alone cannot fix false alarms from a too-short window.\n'
    '  # The additional 1h hold tolerates boundary jitter before paging.\n')
a = replace(a, 'avg_over_time(traffic:backup:attempt_rate:rate5m[2h])', 'avg_over_time(traffic:backup:attempt_rate:rate5m[12h])')
a = replace(a, 'sustained across a 2h window for 1h.', 'sustained across a 12h window for 1h.')
a = replace(a, '    # its own.\n',
    '    # its own.\n'
    '    # The last-run status has no pause-state/freshness information: a\n'
    '    # schedule paused after a failure retains that failure, while one\n'
    '    # paused after a success retains success. It cannot distinguish a\n'
    '    # stale paused result from active failures; check pause state before\n'
    '    # attributing this proxy to storage (ARO-29949).\n')
a = replace(a, 'Over 80% of Velero schedules on management cluster', 'Over 80% of observed Velero 6-hourly schedules on management cluster')
a = replace(a, 'before assuming it is specifically storage."',
    'before assuming it is specifically storage. Paused schedules retain their last status; verify pause state before interpreting this ratio as active failures."')
a = replace(a, '    # docs/alerts.md) against live Velero attempts, scoped to management\n',
    '    # docs/alerts.md) against successful Velero server scrapes, scoped to management\n')
a = replace(a, '        group by (cluster) (velero_backup_attempt_total)\n',
    '        group by (cluster) (up{namespace="velero", pod=~"velero-.+"} == 1)\n')
a = replace(a, '    # clusters never run Velero/HostedCluster backups.\n',
    '    # clusters never run Velero/HostedCluster backups.\n'
    '    # velero/deploy/templates/velero-podmonitor.yaml selects the server;\n'
    '    # its target namespace/pod labels identify Velero rather than node-agent.\n'
    '    # Unlike schedule-labeled counters, up exists on healthy empty MCs.\n'
    '    # One healthy HA scrape is sufficient; both up=0 and missing targets\n'
    '    # are failures. The 15m hold also provides deployment grace.\n')
a = replace(a, 'summary: "no Velero backup metrics reported"', 'summary: "no successful Velero server metrics scrape for 15m"')
a = replace(a,
    'Management cluster {{ $labels.cluster }} is in the underlay-cluster inventory but has reported zero velero_backup_attempt_total samples for 15m. Every other backup alert in this file depends on this metric existing; its absence means Velero itself, its ServiceMonitor, or the whole cluster\'s metrics pipeline may be down, not just an individual backup failing.',
    'Management cluster {{ $labels.cluster }} is in the underlay-cluster inventory but has had no successful Velero server metrics scrape for 15m. Check Velero, its PodMonitor, and the management-cluster metrics pipeline. A healthy empty cluster with up=1 is not a failure merely because it has no backup attempts.')
old_record = y.load(old_r)['spec']['groups'][0]['rules'][0]['expr']
ratio = old_record.split('\nand on (cluster)\n')[0]
denominator = ratio.split('\n/\n',1)[1]
new_record = ratio + '\nand on (cluster)\n(\n' + denominator.rstrip() + '\n> 0\n)\n'
def block(expr):
    return ''.join('        '+line+'\n' for line in expr.rstrip('\n').split('\n'))
r = replace(r, block(old_record), block(new_record))
r = replace(r, '    # Used both as the Traffic baseline-drop alert input and as the ">0" gate\n    # for every other ratio SLI above/below.\n',
    '    # Used as the Traffic baseline-drop alert input and for dashboard\n'
    '    # activity panels. Error and latency gates use completed outcomes.\n')
r = replace(r, '    # fail. Hourly is both the most frequent cadence (fastest to reflect the\n',
    '    # fail. Six-hourly is the most frequent production cadence (first to reflect the\n')
r = replace(r, '    # once ARO-29949 lands.\n',
    '    # once ARO-29949 lands. Paused schedules retain their last status;\n'
    '    # this ratio cannot distinguish stale paused results from active\n'
    '    # failures without schedule pause-state and last-run age metrics.\n')
A.write_text(a)
R.write_text(r)
groups = y.load(a)['spec']['groups']
rules = {q['alert']:q for g in groups for q in g['rules']}
group_labels = {q['alert']:g.get('labels',{}) for g in groups for q in g['rules']}
def render(s, labels, value=1):
    for k,v in labels.items():
        s = s.replace('{{ $labels.'+k+' }}', str(v))
    return s.replace('{{ $value }}', str(value))
t = AT.read_text()
existing = y.load(t)
for item in existing['tests']:
    for assertion in item.get('alert_rule_test',[]):
        name = assertion['alertname']
        for exp in assertion.get('exp_alerts',[]):
            labels = exp.get('exp_labels',{})
            for key, old in exp.get('exp_annotations',{}).items():
                if key in rules[name].get('annotations',{}):
                    value = 11 if name == 'userJourneyBackupRepoMaintenanceSaturation' else 1
                    new = render(rules[name]['annotations'][key], labels, value)
                    if old != new:
                        t = t.replace(old,new)
low_begin = t.index('# Errors volume guard:')
low_end = t.index('# Errors: slow burn', low_begin)
chunk = replace(t[low_begin:low_end], 'eval_time: 62m', 'eval_time: 4m')
t = t[:low_begin]+chunk+t[low_end:]
t = replace(t, 'values: "0+1x1440 1440+0.004x190"', 'values: "0+1x1440 1440+0.004x900"')
t = replace(t, 'eval_time: 27h5m', 'eval_time: 39h')
t = replace(t, 'values: "0 60+0x59 120+0x59 180+0x45"', 'values: "0 60x359 120x359 180x359 240x359 300x359 360x359"')
t = replace(t, 'eval_time: 165m', 'eval_time: 35h')
start = t.index('# Traffic: attempt rate collapses')
end = t.index('- interval:', start)
t = t[:start]+'''# Traffic: after a day of activity, sustained near-zero attempts must fire.
# The recent window now spans 12h (two six-hour production intervals), then
# the condition must hold for another hour. Evaluate at 39h with margin.
# ========================================
'''+t[end:]
start = t.index('# Traffic: healthy 6-hourly-cron-aligned bursts')
end = t.index('- interval:', start)
t = t[:start]+'''# Traffic: healthy synchronized six-hour bursts, with constant counters
# between them. Check near the end of the quiet gap before the next burst;
# a two-hour observation window would incorrectly fire here.
# ========================================
'''+t[end:]
needle = '  - series: \'velero_backup_attempt_total{cluster="int-eastus-mgmt-1", schedule="ns-a-6-hourly"}\'\n    values: "0+1x20"'
t = replace(t, needle, needle+'\n  - series: \'up{cluster="int-eastus-mgmt-1", namespace="velero", pod="velero-server-1"}\'\n    values: "1x20"')
t = t.replace('its ServiceMonitor,', 'its PodMonitor,')
t = t.replace('# MetricsAbsent: a management cluster is in the underlay inventory but has\n# never reported a single velero_backup_attempt_total sample (Velero itself,', '# MetricsAbsent: a management cluster is in the underlay inventory but has\n# no successful Velero server scrape (Velero itself,')
t = t.replace('# A management cluster that IS reporting attempts must never fire, even if', '# A management cluster with a successful server scrape must not fire, even if')
NAMES = {
 'backup_alert': ['healthy_baseline','availability_fast_stale_12h','availability_medium_stale_24h','availability_slow_stale_72h','availability_recovery_after_success','errors_fast_burn','errors_delayed_completion','errors_delayed_low_failure_share_not_infinity','errors_fast_below_volume_floor','errors_slow_burn','latency_medium_breach','latency_medium_healthy','latency_mixed_volumes_breach','latency_mixed_volumes_healthy','traffic_sustained_collapse','traffic_healthy_six_hour_bursts','storage_three_hostedclusters_fail','storage_single_hostedcluster_guard','storage_one_hostedcluster_three_cadences','storage_mixed_cadence_outage','saturation_below_threshold','saturation_nonterminal_backlog','saturation_new_queued_backlog','saturation_queued_and_ready_backlog','metrics_missing_server','metrics_service_cluster_excluded','metrics_healthy_server'],
 'backup_recording': ['errors_completed_outcome_ratio','errors_no_completed_outcomes','errors_missing_unused_failure_counters','latency_histogram_quantile','storage_ratio_and_hostedcluster_count','storage_mixed_cadence_outage','hostedcluster_count_deduplicates_cadences','saturation_counts_nonterminal_phases','saturation_empty_backlog_has_no_series','saturation_includes_queued_and_ready']
}
def add_names(text, kind):
    matches = list(re.finditer(r'^- interval:.*$', text, re.M))
    assert len(matches) == len(NAMES[kind])
    for idx, m in reversed(list(enumerate(matches))):
        text = text[:m.end()] + '\n  name: ' + NAMES[kind][idx] + text[m.end():]
    return text

t = add_names(t,'backup_alert')
rt = add_names(RT.read_text(),'backup_recording')
rt = rt.replace('# Errors ratio guard: zero attempt volume must emit no sample (not NaN or 0) -', '# Errors ratio guard: zero completed volume must emit no sample (not NaN or 0) -')
new_tests = []
def series(metric, vals, **labels):
    label_text = ', '.join(k+'='+json.dumps(str(v)) for k,v in labels.items())
    return {'series':metric+'{'+label_text+'}', 'values':vals}
def expected(name, cluster, value=1, **extra):
    labels = {'alertname':name,'cluster':cluster, **group_labels[name], **rules[name]['labels'], **extra}
    annotations = {k:render(v,labels,value) for k,v in rules[name]['annotations'].items()}
    return {'exp_labels':labels, 'exp_annotations':annotations}
def check(name, time, *alerts):
    return {'eval_time':time, 'alertname':name, 'exp_alerts':list(alerts)}
def case(name, inputs, assertions):
    new_tests.append({'name':name,'interval':'1m','input_series':inputs,'alert_rule_test':assertions})
for tier,window,floor,start,delay in [('1h5m','1h',3,60,3),('6h30m','6h',5,360,20),('3d6h','3d',10,4320,61)]:
    name='userJourneyBackupErrors'+tier
    inputs=[]
    for kind,replicas,volume in [('single-low',1,floor-1),('ha-low',2,floor-1),('ha-floor',2,floor)]:
        for replica in range(replicas):
            labels={'cluster':'guard-'+tier+'-'+kind,'schedule':'ns-a-6-hourly','prometheus_replica':str(replica)}
            val=f'0x{start-1} {volume}x{delay+3}'
            inputs.append(series('velero_backup_attempt_total',val,**labels))
            inputs.append(series('velero_backup_failure_total',val,**labels))
    case('error_'+tier+'_replica_invariant_volume_floor', inputs, [
        check(name,f'{start}m'),
        check(name,f'{start+delay}m',expected(name,'guard-'+tier+'-ha-floor'))])
inputs=[series('velero_backup_attempt_total','0+100x130',cluster='recovery-errors',schedule='ns-a-6-hourly'),
        series('velero_backup_success_total','0+90x80 7300+100x49',cluster='recovery-errors',schedule='ns-a-6-hourly'),
        series('velero_backup_failure_total','0+10x80 800x49',cluster='recovery-errors',schedule='ns-a-6-hourly')]
case('errors_fast_burn_fires_then_recovers_with_successes',inputs,[
    check('userJourneyBackupErrors1h5m','62m',expected('userJourneyBackupErrors1h5m','recovery-errors')),
    check('userJourneyBackupErrors1h5m','86m')])
slow='userJourneyBackupLatency3d6h'
medium='userJourneyBackupLatency6h30m'
inputs=[series('velero_backup_duration_seconds_bucket','0x4380 100+100x419',cluster='latency-recovery',schedule='ns-a-6-hourly',le='1200'),
        series('velero_backup_duration_seconds_bucket','0+100x4800',cluster='latency-recovery',schedule='ns-a-6-hourly',le='1800'),
        series('velero_backup_duration_seconds_bucket','0+100x4800',cluster='latency-recovery',schedule='ns-a-6-hourly',le='+Inf')]
case('latency_slow_pending_firing_and_short_window_recovery',inputs,[
    check(slow,'60m'),check(slow,'61m',expected(slow,'latency-recovery')),
    check(slow,'73h',expected(slow,'latency-recovery')),
    check(medium,'73h',expected(medium,'latency-recovery')),
    check(medium,'74h'),check(slow,'80h')])
inputs=[series('velero_backup_duration_seconds_bucket','0+2x4380',cluster='latency-healthy',schedule='ns-a-6-hourly',le=le) for le in ('300','1200','1800','+Inf')]
case('latency_slow_healthy_full_three_day_history',inputs,[check(slow,'73h')])
inputs=[series('velero_backup_duration_seconds_bucket','0+100x3960 396000x359',cluster='latency-long-healthy',schedule='ns-a-6-hourly',le='1200')]
for le in ('1800','+Inf'):
    inputs.append(series('velero_backup_duration_seconds_bucket','0+100x3960 396001+1x359',cluster='latency-long-healthy',schedule='ns-a-6-hourly',le=le))
case('latency_slow_short_breach_cannot_bypass_healthy_long_window',inputs,[check(slow,'72h')])
def encode_constant_runs(values):
    runs=[];start=0
    for i in range(1,len(values)+1):
        if i==len(values) or values[i]!=values[start]:
            n=i-start
            runs.append(str(values[start])+(f'x{n-1}' if n>1 else ''))
            start=i
    return ' '.join(runs)
values=[];count=0
for minute in range(2161):
    if minute in (1,361,721,1081,1981):count+=60
    values.append(count)
case('traffic_six_hour_bursts_stop_and_recover',[
    series('velero_backup_attempt_total',encode_constant_runs(values),cluster='traffic-recovery',schedule='ns-a-6-hourly')],[
    check('userJourneyBackupTraffic','23h'),
    check('userJourneyBackupTraffic','32h',expected('userJourneyBackupTraffic','traffic-recovery')),
    check('userJourneyBackupTraffic','34h')])
values=[];count=0
for minute in range(2161):
    if minute%360==1:count+=60
    values.append(count)
case('traffic_never_fires_between_healthy_six_hour_bursts',[
    series('velero_backup_attempt_total',encode_constant_runs(values),cluster='traffic-healthy',schedule='ns-a-6-hourly')],
    [check('userJourneyBackupTraffic',f'{minute}m') for minute in range(120,2161,15)])
inputs=[series('velero_backup_last_status','0x20 1x19',cluster='storage-recovery',schedule=f'ns-{hc}-6-hourly') for hc in ('a','b','c')]
case('storage_proxy_failed_last_runs_then_successful_recovery',inputs,[
    check('userJourneyBackupStorageAvailability','17m',expected('userJourneyBackupStorageAvailability','storage-recovery')),
    check('userJourneyBackupStorageAvailability','23m')])
inputs=[]
for n in range(11):
    inputs += [series('velerobackup_phase','1x215 0x14',cluster='queue-recovery',namespace='velero',name=f'backup-{n}',phase='Queued'),
               series('velerobackup_phase','0x215 1x14',cluster='queue-recovery',namespace='velero',name=f'backup-{n}',phase='Completed')]
case('saturation_sustained_backlog_then_completed_backups',inputs,[
    check('userJourneyBackupRepoMaintenanceSaturation','209m'),
    check('userJourneyBackupRepoMaintenanceSaturation','215m',expected('userJourneyBackupRepoMaintenanceSaturation','queue-recovery',11)),
    check('userJourneyBackupRepoMaintenanceSaturation','218m')])
missing='userJourneyBackupMetricsAbsent'
inputs=[series('underlay_clusters','1x50',cluster='int-eastus-mgmt-recovery'),
        series('up','0x20 1x29',cluster='int-eastus-mgmt-recovery',namespace='velero',pod='velero-server-1')]
case('metrics_absent_failed_scrapes_then_healthy_recovery',inputs,[
    check(missing,'14m'),check(missing,'17m',expected(missing,'int-eastus-mgmt-recovery')),check(missing,'22m')])
case('metrics_absent_empty_cluster_with_healthy_server_and_no_attempts',[
    series('underlay_clusters','1x30',cluster='int-eastus-mgmt-empty'),
    series('up','1x30',cluster='int-eastus-mgmt-empty',namespace='velero',pod='velero-server-1')],[check(missing,'25m')])
case('metrics_absent_one_healthy_ha_scrape_prevents_false_alarm',[
    series('underlay_clusters','1x30',cluster='int-eastus-mgmt-ha'),
    series('up','0x30',cluster='int-eastus-mgmt-ha',namespace='velero',pod='velero-server-1',prometheus_replica='0'),
    series('up','1x30',cluster='int-eastus-mgmt-ha',namespace='velero',pod='velero-server-1',prometheus_replica='1')],[check(missing,'25m')])
case('metrics_absent_node_agent_does_not_mask_missing_server',[
    series('underlay_clusters','1x30',cluster='int-eastus-mgmt-server-missing'),
    series('up','1x30',cluster='int-eastus-mgmt-server-missing',namespace='velero',pod='node-agent-1')],[check(missing,'25m',expected(missing,'int-eastus-mgmt-server-missing'))])
never='userJourneyBackupNeverSucceeded'
inputs=[series('velero_backup_last_status','0x800',cluster='never-success',schedule='ns-never-6-hourly'),
        series('velero_backup_attempt_total','0+1x800',cluster='never-success',schedule='ns-never-6-hourly'),
        series('velero_backup_last_successful_timestamp','_x741 44460x59',cluster='never-success',schedule='ns-never-6-hourly'),
        series('velero_backup_last_status','1x800',cluster='never-success',schedule='ns-healthy-6-hourly'),
        series('velero_backup_last_successful_timestamp','0+60x800',cluster='never-success',schedule='ns-healthy-6-hourly')]
case('never_succeeded_observed_status_grace_healthy_sibling_and_first_success',inputs,[
    check(never,'719m'),check(never,'720m',expected(never,'never-success',hosted_cluster_namespace='ns-never')),
    check(never,'740m',expected(never,'never-success',hosted_cluster_namespace='ns-never')),check(never,'742m')])
case('never_succeeded_no_schedule_inventory_is_not_fabricated',[],[check(never,'13h')])
case('never_succeeded_daily_schedule_not_treated_as_production_six_hourly',[
    series('velero_backup_last_status','0x800',cluster='never-daily',schedule='ns-daily-daily')],[check(never,'13h')])
buf=io.StringIO();y.dump({'tests':new_tests},buf)
appended=buf.getvalue().split('\n',1)[1]
assert appended.startswith('- ')
t=t.rstrip()+'\n# Review regression and recovery scenarios.\n'+appended
AT.write_text(t)
recording_test={'name':'error_ratio_delayed_completions_without_recent_attempts','interval':'1m','input_series':[
    series('velero_backup_attempt_total','0 50x19',cluster='delayed',schedule='ns-a-6-hourly'),
    series('velero_backup_failure_total','0x9 4x10',cluster='delayed',schedule='ns-a-6-hourly'),
    series('velero_backup_success_total','0x9 46x10',cluster='delayed',schedule='ns-a-6-hourly')],
    'promql_expr_test':[
        {'expr':'round(errors:backup:ratio:rate5m{cluster="delayed"} * 100)','eval_time':'12m','exp_samples':[{'labels':'{cluster="delayed"}','value':8}]},
        {'expr':'errors:backup:ratio:rate5m{cluster="delayed"}','eval_time':'18m','exp_samples':[]}]}
buf=io.StringIO();y.dump({'tests':[recording_test]},buf)
rt=rt.rstrip()+'\n# Delayed outcomes must remain visible in the diagnostic SLI.\n'+buf.getvalue().split('\n',1)[1]
RT.write_text(rt)
generator=ROOT/'tooling/prometheus-rules/internal/generator.go'
g=generator.read_text()
g=replace(g,'\t\t\t\t\tfor _, label := range extractedLabels {\n\t\t\t\t\t\tif !strings.Contains(title, labelTemplateToken(label)) {',
    '\t\t\t\t\tfor _, label := range extractedLabels {\n'
    '\t\t\t\t\t\t// writeAlertGroups prefixes IcM.Title with the cluster label.\n'
    '\t\t\t\t\t\t// Requiring it in summary too would duplicate it in the title.\n'
    '\t\t\t\t\t\tif label == "cluster" {\n'
    '\t\t\t\t\t\t\tcontinue\n'
    '\t\t\t\t\t\t}\n'
    '\t\t\t\t\t\tif !strings.Contains(title, labelTemplateToken(label)) {')
generator.write_text(g)
gt=ROOT/'tooling/prometheus-rules/internal/generator_test.go'
g=gt.read_text()
start=g.index('t.Run("enriches default correlationId using labelsToExtract"')
end=g.index('t.Run("labelsToExtract orders labels',start)
part=g[start:end]
part=replace(part,'"description": "Pod {{ $labels.namespace }}/{{ $labels.pod }} has issues",','"description": "Pod {{ $labels.namespace }}/{{ $labels.pod }} on {{ $labels.cluster }} has issues",')
before='\t\tassert.Contains(t, generated, "title: \'Pod {{ $labels.namespace }}/{{ $labels.pod }} is unhealthy\'")'
part=replace(part,before,before+'\n\t\tassert.Contains(t, generated, "\'IcM.Title\': \'#$.labels.cluster#: #$.annotations.title#\'")')
gt.write_text(g[:start]+part+g[end:])
final_tests=y.load(AT.read_text())
assert len({q['name'] for q in final_tests['tests']})==len(final_tests['tests'])
assert {q['alertname'] for c in final_tests['tests'] for q in c.get('alert_rule_test',[])}==set(rules)
assert len(rules)==13
assert 'schedule=~".+-hourly"' not in r
assert all('$labels.cluster' not in q['annotations']['summary'] for q in rules.values())
print('Review implementation:',len(rules),'alerts;',len(final_tests['tests']),'named alert scenarios;',len(y.load(rt)['tests']),'named recording scenarios.')
print('Pre-hook timeout source line:',hook_line)
for c in final_tests['tests']:print('SCENARIO:',c['name'])
