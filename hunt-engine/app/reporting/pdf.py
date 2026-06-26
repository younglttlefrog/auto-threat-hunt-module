from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
import html


def markdown_to_pdf(markdown_text: str, output_file: str):
    doc = SimpleDocTemplate(
        output_file,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
    )

    styles = getSampleStyleSheet()
    story = []

    for line in markdown_text.splitlines():
        safe = html.escape(line)

        if line.startswith("# "):
            story.append(Paragraph(f"<b>{safe[2:]}</b>", styles["Title"]))
            story.append(Spacer(1, 10))
        elif line.startswith("## "):
            story.append(Paragraph(f"<b>{safe[3:]}</b>", styles["Heading2"]))
            story.append(Spacer(1, 8))
        elif line.startswith("### "):
            story.append(Paragraph(f"<b>{safe[4:]}</b>", styles["Heading3"]))
            story.append(Spacer(1, 6))
        elif line.startswith("- "):
            story.append(Paragraph(f"• {safe[2:]}", styles["BodyText"]))
        elif line.strip() == "":
            story.append(Spacer(1, 6))
        elif line.startswith("|"):
            story.append(Paragraph(safe, styles["Code"]))
        else:
            story.append(Paragraph(safe, styles["BodyText"]))

    doc.build(story)
