#!/usr/bin/env python3
"""Generate benchmark comparison SVG plots for curldbg vs curl."""

import matplotlib
matplotlib.use('SVG')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

OUT_DIR = 'docs/benchmarks'

# Data: all values in milliseconds
# 200-iterations each, httpbin.org
data = {
    'Single GET': {
        'before': {'curldbg': {'mean': 596.16, 'median': 509.75, 'p95': 1004.43},
                   'curl':    {'mean': 583.57, 'median': 510.46, 'p95': 729.16}},
        'after':  {'curldbg': {'mean': 570.05, 'median': 517.85, 'p95': 778.92},
                   'curl':    {'mean': 543.25, 'median': 500.46, 'p95': 799.10}},
    },
    '1 Redirect': {
        'before': {'curldbg': {'mean': 726.17, 'median': 666.85, 'p95': 1085.03},
                   'curl':    {'mean': 857.24, 'median': 631.38, 'p95': 1123.69}},
        'after':  {'curldbg': {'mean': 706.85, 'median': 688.54, 'p95': 1075.16},
                   'curl':    {'mean': 727.98, 'median': 622.87, 'p95': 1058.21}},
    },
    '5 Redirects': {
        'before': {'curldbg': {'mean': 1630.91, 'median': 1474.03, 'p95': 2251.94},
                   'curl':    {'mean': 1673.88, 'median': 1335.93, 'p95': 2143.09}},
        'after':  {'curldbg': {'mean': 1495.97, 'median': 1306.08, 'p95': 2292.00},
                   'curl':    {'mean': 1446.92, 'median': 1327.16, 'p95': 2083.73}},
    },
    'No Happy Eyeballs': {
        'before': {'curldbg': {'mean': 577.82, 'median': 560.60, 'p95': 815.06},
                   'curl':    {'mean': 537.07, 'median': 503.14, 'p95': 803.79}},
        'after':  {'curldbg': {'mean': 513.76, 'median': 450.93, 'p95': 784.65},
                   'curl':    {'mean': 536.43, 'median': 500.98, 'p95': 713.99}},
    },
}

scenarios = list(data.keys())
metrics = ['median', 'mean', 'p95']
metric_labels = ['Median', 'Mean', 'P95']

def dark_theme():
    plt.rcParams.update({
        'figure.facecolor': '#1e1e2e',
        'axes.facecolor': '#1e1e2e',
        'axes.edgecolor': '#cdd6f4',
        'axes.labelcolor': '#cdd6f4',
        'axes.titlecolor': '#cdd6f4',
        'text.color': '#cdd6f4',
        'xtick.color': '#cdd6f4',
        'ytick.color': '#cdd6f4',
        'legend.facecolor': '#1e1e2e',
        'legend.edgecolor': '#585b70',
        'legend.labelcolor': '#cdd6f4',
        'grid.color': '#313244',
    })

# Colors
BEFORE_C = '#f38ba8'   # red
AFTER_C  = '#a6e3a1'   # green
CURL_C   = '#89b4fa'   # blue

def plot_scenario_metric(scenario, metric, metric_label):
    """Bar chart: before/after curldbg + curl-after for one scenario/metric."""
    d = data[scenario]
    before_val = d['before']['curldbg'][metric]
    after_val  = d['after']['curldbg'][metric]
    curl_val   = d['after']['curl'][metric]

    fig, ax = plt.subplots(figsize=(5, 4))
    labels = ['curldbg\n(before)', 'curldbg\n(after)', 'curl']
    values = [before_val, after_val, curl_val]
    colors = [BEFORE_C, AFTER_C, CURL_C]
    bars = ax.bar(labels, values, color=colors, edgecolor='#585b70', linewidth=0.8, width=0.5)

    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(values)*0.02,
                f'{val:.0f} ms', ha='center', va='bottom', fontsize=9, color='#cdd6f4')

    delta = ((after_val - before_val) / before_val) * 100
    ax.set_title(f'{scenario} — {metric_label}', fontsize=13, fontweight='bold', pad=12)
    ax.set_ylabel('Milliseconds', fontsize=10)
    ax.set_ylim(0, max(values) * 1.15)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter('%d'))
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

    # Add delta annotation
    ax.annotate(f'Δ = {delta:+.1f}%',
                xy=(1, after_val), xytext=(0.75, after_val + max(values)*0.06),
                fontsize=9, color=AFTER_C, fontweight='bold',
                arrowprops=dict(arrowstyle='->', color=AFTER_C, lw=1.2))

    fig.tight_layout()
    safe = scenario.lower().replace(' ', '_')
    path = f'{OUT_DIR}/{safe}_{metric}.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

def plot_all_medians():
    """Grouped bar: median before/after for all scenarios."""
    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(scenarios))
    w = 0.25

    before_vals = [data[s]['before']['curldbg']['median'] for s in scenarios]
    after_vals  = [data[s]['after']['curldbg']['median'] for s in scenarios]
    curl_vals   = [data[s]['after']['curl']['median'] for s in scenarios]

    ax.bar(x - w, before_vals, w, label='curldbg before', color=BEFORE_C, edgecolor='#585b70', linewidth=0.6)
    ax.bar(x,      after_vals,  w, label='curldbg after',  color=AFTER_C,  edgecolor='#585b70', linewidth=0.6)
    ax.bar(x + w, curl_vals,   w, label='curl',            color=CURL_C,   edgecolor='#585b70', linewidth=0.6)

    ax.set_xticks(x)
    ax.set_xticklabels(scenarios, fontsize=10)
    ax.set_ylabel('Median time (ms)', fontsize=11)
    ax.set_title('Median Latency Comparison — curldbg vs curl', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)
    ax.yaxis.set_major_formatter(mticker.FormatStrFormatter('%d'))

    fig.tight_layout()
    path = f'{OUT_DIR}/all_medians.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

def plot_p95_comparison():
    """P95 before/after for single GET and 1/5 redirects."""
    fig, ax = plt.subplots(figsize=(6, 4))
    targets = ['Single GET', '1 Redirect', '5 Redirects']
    x = np.arange(len(targets))
    w = 0.25

    before_vals = [data[t]['before']['curldbg']['p95'] for t in targets]
    after_vals  = [data[t]['after']['curldbg']['p95'] for t in targets]
    curl_vals   = [data[t]['after']['curl']['p95'] for t in targets]

    ax.bar(x - w, before_vals, w, label='curldbg before', color=BEFORE_C, edgecolor='#585b70', linewidth=0.6)
    ax.bar(x,      after_vals,  w, label='curldbg after',  color=AFTER_C,  edgecolor='#585b70', linewidth=0.6)
    ax.bar(x + w, curl_vals,   w, label='curl',            color=CURL_C,   edgecolor='#585b70', linewidth=0.6)

    for i in range(len(targets)):
        ax.text(i, after_vals[i] + 20, f'{after_vals[i]:.0f}',
                ha='center', va='bottom', fontsize=8, color=AFTER_C, fontweight='bold')

    ax.set_xticks(x)
    ax.set_xticklabels(targets, fontsize=10)
    ax.set_ylabel('P95 time (ms)', fontsize=11)
    ax.set_title('P95 Tail Latency — curldbg before/after vs curl', fontsize=13, fontweight='bold')
    ax.legend(fontsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', alpha=0.3)

    fig.tight_layout()
    path = f'{OUT_DIR}/p95_comparison.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

def plot_delta_heatmap():
    """Heatmap of % change (after vs before) and (after vs curl) for each scenario/metric."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8, 4))

    scenarios_short = ['GET', '1R', '5R', 'NoHE']

    self_delta = np.array([[ ((data[s]['after']['curldbg'][m] - data[s]['before']['curldbg'][m])
                               / data[s]['before']['curldbg'][m]) * 100
                             for m in metrics] for s in scenarios])

    vs_curl_delta = np.array([[ ((data[s]['after']['curldbg'][m] - data[s]['after']['curl'][m])
                                  / data[s]['after']['curl'][m]) * 100
                                for m in metrics] for s in scenarios])

    im1 = ax1.imshow(self_delta, cmap='RdYlGn', vmin=-25, vmax=25, aspect='auto')
    ax1.set_xticks(range(len(metrics)))
    ax1.set_xticklabels(metric_labels, fontsize=9)
    ax1.set_yticks(range(len(scenarios_short)))
    ax1.set_yticklabels(scenarios_short, fontsize=9)
    ax1.set_title('curldbg after vs before (%)', fontsize=11, fontweight='bold')
    for i in range(len(scenarios_short)):
        for j in range(len(metrics)):
            val = self_delta[i, j]
            c = 'white' if abs(val) > 12 else '#cdd6f4'
            ax1.text(j, i, f'{val:+.1f}%', ha='center', va='center', fontsize=8, color=c)

    im2 = ax2.imshow(vs_curl_delta, cmap='RdYlGn', vmin=-25, vmax=25, aspect='auto')
    ax2.set_xticks(range(len(metrics)))
    ax2.set_xticklabels(metric_labels, fontsize=9)
    ax2.set_yticks(range(len(scenarios_short)))
    ax2.set_yticklabels(scenarios_short, fontsize=9)
    ax2.set_title('curldbg after vs curl (%)', fontsize=11, fontweight='bold')
    for i in range(len(scenarios_short)):
        for j in range(len(metrics)):
            val = vs_curl_delta[i, j]
            c = 'white' if abs(val) > 12 else '#cdd6f4'
            ax2.text(j, i, f'{val:+.1f}%', ha='center', va='center', fontsize=8, color=c)

    fig.tight_layout()
    path = f'{OUT_DIR}/delta_heatmap.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

if __name__ == '__main__':
    dark_theme()
    print('Generating plots...')
    for s in scenarios:
        for m, ml in zip(metrics, metric_labels):
            plot_scenario_metric(s, m, ml)
    plot_all_medians()
    plot_p95_comparison()
    plot_delta_heatmap()
    print('Done.')
