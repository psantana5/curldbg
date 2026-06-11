#!/usr/bin/env python3
"""Generate benchmark comparison SVG plots for curldbg vs curl."""

import matplotlib
matplotlib.use('SVG')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

OUT_DIR = 'docs/benchmarks'

# Local benchmark data (500 iterations, Docker httpbin on loopback)
local = {
    'Single GET': {
        'curldbg': {'mean': 2.68, 'median': 2.56, 'p95': 3.83},
        'curl':    {'mean': 2.32, 'median': 2.20, 'p95': 3.39},
    },
    '1 Redirect': {
        'curldbg': {'mean': 3.76, 'median': 3.66, 'p95': 5.53},
        'curl':    {'mean': 3.70, 'median': 3.56, 'p95': 5.10},
    },
    '3 Redirects': {
        'curldbg': {'mean': 5.52, 'median': 5.33, 'p95': 8.03},
        'curl':    {'mean': 5.46, 'median': 5.46, 'p95': 7.80},
    },
    '5 Redirects': {
        'curldbg': {'mean': 6.40, 'median': 6.09, 'p95': 9.47},
        'curl':    {'mean': 6.93, 'median': 6.89, 'p95': 9.97},
    },
}

# Remote benchmark data (200 iterations, httpbin.org via internet)
remote = {
    'Single GET': {
        'curldbg': {'mean': 499.24, 'median': 465.11, 'p95': 756.33},
        'curl':    {'mean': 489.53, 'median': 461.42, 'p95': 658.99},
    },
    '1 Redirect': {
        'curldbg': {'mean': 654.40, 'median': 623.75, 'p95': 981.74},
        'curl':    {'mean': 734.52, 'median': 620.96, 'p95': 945.03},
    },
}

# Over-time data showing progression across optimization rounds
# (all remote httpbin.org, 200 iters)
progression = {
    'Single GET P95': {
        'baseline': 1004.43,
        '+warmup+reuse': 778.92,
        '+NODELAY+DNS+HE': 756.33,
    },
    'Single GET median': {
        'baseline': 509.75,
        '+warmup+reuse': 517.85,
        '+NODELAY+DNS+HE': 465.11,
    },
    '1 Redirect mean': {
        'baseline': 726.17,
        '+warmup+reuse': 706.85,
        '+NODELAY+DNS+HE': 654.40,
    },
}

CURLDBG_C = '#a6e3a1'
CURL_C    = '#89b4fa'
PROG_C    = ['#f38ba8', '#fab387', '#a6e3a1']

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

def plot_local():
    """Grouped bar chart for local benchmark (ms scale)."""
    scenarios = list(local.keys())
    metrics = ['median', 'mean', 'p95']

    for metric in metrics:
        fig, ax = plt.subplots(figsize=(6, 4))
        x = np.arange(len(scenarios))
        w = 0.3
        curldbg_vals = [local[s][metric] for s in scenarios]
        curl_vals = [local[s][metric] for s in scenarios]
        bars1 = ax.bar(x - w/2, curldbg_vals, w, label='curldbg', color=CURLDBG_C, edgecolor='#585b70', linewidth=0.6)
        bars2 = ax.bar(x + w/2, curl_vals, w, label='curl', color=CURL_C, edgecolor='#585b70', linewidth=0.6)

        for bar, val in zip(bars1, curldbg_vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    f'{val:.2f}', ha='center', va='bottom', fontsize=8, color=CURLDBG_C, fontweight='bold')
        for bar, val in zip(bars2, curl_vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    f'{val:.2f}', ha='center', va='bottom', fontsize=8, color=CURL_C)

        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, fontsize=10)
        ax.set_ylabel('Milliseconds', fontsize=10)
        ax.set_title(f'Local benchmark — {metric.capitalize()} (lower is better)', fontsize=12, fontweight='bold')
        ax.legend(fontsize=9)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='y', alpha=0.3)
        fig.tight_layout()
        path = f'{OUT_DIR}/local_{metric}.svg'
        fig.savefig(path, dpi=150)
        plt.close(fig)
        print(f'  wrote {path}')

def plot_remote():
    """Grouped bar chart for remote benchmark (ms scale)."""
    scenarios = list(remote.keys())
    metrics = ['median', 'mean', 'p95']

    for metric in metrics:
        fig, ax = plt.subplots(figsize=(5, 4))
        x = np.arange(len(scenarios))
        w = 0.3
        curldbg_vals = [remote[s][metric] for s in scenarios]
        curl_vals = [remote[s][metric] for s in scenarios]
        bars1 = ax.bar(x - w/2, curldbg_vals, w, label='curldbg', color=CURLDBG_C, edgecolor='#585b70', linewidth=0.6)
        bars2 = ax.bar(x + w/2, curl_vals, w, label='curl', color=CURL_C, edgecolor='#585b70', linewidth=0.6)

        for bar, val in zip(bars1, curldbg_vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15,
                    f'{val:.0f}', ha='center', va='bottom', fontsize=8, color=CURLDBG_C, fontweight='bold')
        for bar, val in zip(bars2, curl_vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 15,
                    f'{val:.0f}', ha='center', va='bottom', fontsize=8, color=CURL_C)

        ax.set_xticks(x)
        ax.set_xticklabels(scenarios, fontsize=10)
        ax.set_ylabel('Milliseconds', fontsize=10)
        ax.set_title(f'Remote benchmark — {metric.capitalize()} (lower is better)', fontsize=12, fontweight='bold')
        ax.legend(fontsize=9)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='y', alpha=0.3)
        ymax = max(max(curldbg_vals), max(curl_vals))
        ax.set_ylim(0, ymax * 1.2)
        fig.tight_layout()
        path = f'{OUT_DIR}/remote_{metric}.svg'
        fig.savefig(path, dpi=150)
        plt.close(fig)
        print(f'  wrote {path}')

def plot_progression():
    """Show improvement over time for key metrics."""
    items = list(progression.items())
    n_items = len(items)

    fig, axes = plt.subplots(1, n_items, figsize=(7, 4))

    for ax, (title, data) in zip(axes, items):
        labels = list(data.keys())
        vals = list(data.values())
        colors = PROG_C[:len(vals)]
        bars = ax.bar(range(len(vals)), vals, color=colors, edgecolor='#585b70', linewidth=0.6, width=0.5)
        for bar, val in zip(bars, vals):
            if val > max(vals) * 0.5:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() - max(vals)*0.04,
                        f'{val:.0f}', ha='center', va='top', fontsize=8, fontweight='bold', color='#1e1e2e')
            else:
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(vals)*0.02,
                        f'{val:.0f}', ha='center', va='bottom', fontsize=8, color='#cdd6f4')

        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, fontsize=7, rotation=20, ha='right')
        ax.set_title(title, fontsize=10, fontweight='bold')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.grid(axis='y', alpha=0.3)
        ax.set_ylim(0, max(vals) * 1.25)

    fig.tight_layout()
    path = f'{OUT_DIR}/progression.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

def plot_local_heatmap():
    """Percentage deltas for local benchmark (curldbg vs curl)."""
    scenarios = list(local.keys())
    metrics = ['median', 'mean', 'p95']
    metric_labels = ['Median', 'Mean', 'P95']

    delta = np.array([[(local[s]['curldbg'][m] - local[s]['curl'][m]) / local[s]['curl'][m] * 100
                       for m in metrics] for s in scenarios])

    fig, ax = plt.subplots(figsize=(5.5, 3.5))
    im = ax.imshow(delta, cmap='RdYlGn', vmin=-15, vmax=15, aspect='auto')
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels(metric_labels, fontsize=9)
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels(scenarios, fontsize=9)
    ax.set_title('curldbg vs curl — local benchmark Δ%', fontsize=11, fontweight='bold')
    for i in range(len(scenarios)):
        for j in range(len(metrics)):
            val = delta[i, j]
            c = 'white' if abs(val) > 8 else '#cdd6f4'
            ax.text(j, i, f'{val:+.1f}%', ha='center', va='center', fontsize=9, color=c, fontweight='bold')
    fig.tight_layout()
    path = f'{OUT_DIR}/local_heatmap.svg'
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f'  wrote {path}')

if __name__ == '__main__':
    dark_theme()
    print('Generating plots...')
    plot_local()
    plot_remote()
    plot_progression()
    plot_local_heatmap()
    print('Done.')
