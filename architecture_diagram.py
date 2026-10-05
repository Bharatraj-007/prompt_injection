import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def generate_diagram():
    fig, ax = plt.subplots(figsize=(10, 8), dpi=200)
    ax.axis('off')

    # Colors
    c_input = "#34495E"
    c_l1 = "#3498DB"
    c_l2 = "#E67E22"
    c_l3 = "#9B59B6"
    c_l4 = "#E74C3C"
    c_l5 = "#2ECC71"
    c_l6 = "#F1C40F"
    c_output = "#1ABC9C"

    # Draw boxes
    boxes = [
        ("Raw Input Prompt\n(System + Untrusted User Text)", 0.35, 0.88, c_input),
        ("Layer 1: Preprocessing\n(NFKC Unicode, Hidden Char Strip, Base64 Decode)", 0.35, 0.76, c_l1),
        ("Layer 2: Rule Filter\n(Multi-Lingual Regex & Heuristics)", 0.15, 0.62, c_l2),
        ("Layer 3: Transformer Model\n(DeBERTa-v3 / DistilBERT Classifier)", 0.55, 0.62, c_l3),
        ("Layer 4: Score Fusion & Thresholding\n(Fused Score = 0.3 * L2 + 0.7 * L3)", 0.35, 0.48, c_l4),
        ("Layer 5: Prompt Hardening & Canary Token\n(Inject dynamic dynamic token instructions)", 0.35, 0.34, c_l5),
        ("Target LLM Inference\n(Generates Raw Response)", 0.35, 0.22, c_input),
        ("Layer 6: Output Guard\n(Canary Leakage & Secret Redaction)", 0.35, 0.10, c_l6),
        ("Guarded Final Output\n(ALLOWED / BLOCKED)", 0.35, -0.02, c_output)
    ]

    for label, x, y, col in boxes:
        box = patches.FancyBboxPatch(
            (x - 0.2, y - 0.04), 0.4, 0.07,
            boxstyle="round,pad=0.02", ec="black", fc=col, alpha=0.85
        )
        ax.add_patch(box)
        ax.text(x, y, label, ha="center", va="center", color="white", fontsize=9, fontweight="bold")

    # Connectors
    arrows = [
        ((0.35, 0.84), (0.35, 0.80)),
        ((0.35, 0.72), (0.20, 0.66)),
        ((0.35, 0.72), (0.50, 0.66)),
        ((0.20, 0.58), (0.30, 0.52)),
        ((0.50, 0.58), (0.40, 0.52)),
        ((0.35, 0.44), (0.35, 0.38)),
        ((0.35, 0.30), (0.35, 0.26)),
        ((0.35, 0.18), (0.35, 0.14)),
        ((0.35, 0.06), (0.35, 0.02))
    ]

    for start, end in arrows:
        ax.annotate(
            "", xy=end, xytext=start,
            arrowprops=dict(arrowstyle="->", color="black", lw=1.5)
        )

    plt.title("Multi-Layered Prompt Injection Detection & Defense Architecture", fontsize=12, fontweight="bold", pad=20)
    plots_dir = os.path.join(os.getcwd(), "plots")
    os.makedirs(plots_dir, exist_ok=True)
    out_path = os.path.join(plots_dir, "architecture_diagram.png")
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[OK] Saved architecture diagram to {out_path}")

if __name__ == "__main__":
    generate_diagram()
