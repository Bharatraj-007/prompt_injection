"""
Architecture Diagram Generator for 7-Layer Hybrid Prompt Injection Defense
Generates high-resolution architecture diagrams for publication and documentation.
"""
import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

def generate_diagram():
    fig, ax = plt.subplots(figsize=(11, 9), dpi=200)
    ax.axis('off')

    # Colors
    c_input = "#2C3E50"
    c_l1 = "#2980B9"
    c_l2 = "#D35400"
    c_l3 = "#8E44AD"
    c_l7 = "#16A085"
    c_l4 = "#C0392B"
    c_l5 = "#27AE60"
    c_l6 = "#F39C12"
    c_output = "#2C3E50"

    # Draw boxes
    boxes = [
        ("Raw Untrusted Input Prompt\n(Direct / Indirect / Obfuscated Vectors)", 0.50, 0.92, 0.52, 0.06, c_input),
        ("Layer 1: Preprocessing & Obfuscation Decoding\n(NFKC Unicode, Hidden Characters, Hex / Base64 Decoding)", 0.50, 0.81, 0.58, 0.06, c_l1),
        ("Layer 2: Rule Filter\n(Regex Heuristics)", 0.20, 0.68, 0.26, 0.06, c_l2),
        ("Layer 3: DistilBERT Model\n(Fine-Tuned Embeddings)", 0.50, 0.68, 0.26, 0.06, c_l3),
        ("Layer 7: LLM as a Judge\n(Groq / xAI / Local GPU)", 0.80, 0.68, 0.26, 0.06, c_l7),
        ("Layer 4: Multi-Layer Probabilistic Score Fusion\n(Noisy-OR Formulation: 1 - (1-r)*(1-m)*(1-j))", 0.50, 0.54, 0.60, 0.06, c_l4),
        ("Layer 5: Canary Hardening & Boundary Defense\n(Demarcation Enclosures & Cryptographic Secrets)", 0.50, 0.41, 0.58, 0.06, c_l5),
        ("Target LLM Generation Step\n(Customer Assistant / Task Executor)", 0.50, 0.28, 0.50, 0.06, c_input),
        ("Layer 6: Output Guard & Canary Verifier\n(Egress Inspection, Canary Leak Audit, Redaction)", 0.50, 0.15, 0.58, 0.06, c_l6),
        ("Guarded Final Output\n(ALLOWED / BLOCKED / REDACTED)", 0.50, 0.02, 0.50, 0.06, c_output)
    ]

    for label, x, y, w, h, col in boxes:
        box = patches.FancyBboxPatch(
            (x - w / 2, y - h / 2), w, h,
            boxstyle="round,pad=0.015", ec="black", fc=col, alpha=0.90
        )
        ax.add_patch(box)
        ax.text(x, y, label, ha="center", va="center", color="white", fontsize=8.5, fontweight="bold")

    # Connectors
    arrows = [
        ((0.50, 0.89), (0.50, 0.84)),  # Input -> L1
        ((0.35, 0.78), (0.20, 0.71)),  # L1 -> L2
        ((0.50, 0.78), (0.50, 0.71)),  # L1 -> L3
        ((0.65, 0.78), (0.80, 0.71)),  # L1 -> L7
        ((0.20, 0.65), (0.35, 0.57)),  # L2 -> L4
        ((0.50, 0.65), (0.50, 0.57)),  # L3 -> L4
        ((0.80, 0.65), (0.65, 0.57)),  # L7 -> L4
        ((0.50, 0.51), (0.50, 0.44)),  # L4 -> L5
        ((0.50, 0.38), (0.50, 0.31)),  # L5 -> Target LLM
        ((0.50, 0.25), (0.50, 0.18)),  # Target LLM -> L6
        ((0.50, 0.12), (0.50, 0.05))   # L6 -> Final Output
    ]

    for start, end in arrows:
        ax.annotate(
            "", xy=end, xytext=start,
            arrowprops=dict(arrowstyle="->", color="#1A252F", lw=1.6)
        )

    plt.title("7-Layer Hybrid Defense Pipeline Architecture with LLM as a Judge", fontsize=13, fontweight="bold", pad=25)
    plots_dir = os.path.join(os.getcwd(), "plots")
    os.makedirs(plots_dir, exist_ok=True)
    out_path = os.path.join(plots_dir, "architecture_diagram.png")
    plt.savefig(out_path, bbox_inches='tight')
    plt.close()
    print(f"[OK] Generated 7-layer architecture diagram: {out_path}")

if __name__ == "__main__":
    generate_diagram()
