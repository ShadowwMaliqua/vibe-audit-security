import PDFDocument from "pdfkit";
import type { Finding, ScanResult, Severity } from "../types.js";

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  info: "#6b7280",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const GRADE_COLORS: Record<string, string> = {
  A: "#16a34a",
  B: "#65a30d",
  C: "#d97706",
  D: "#ea580c",
  F: "#dc2626",
};

const TEXT_COLOR = "#111827";
const MUTED_COLOR = "#6b7280";
const RULE_COLOR = "#e5e7eb";

function renderCoverPage(doc: PDFKit.PDFDocument, result: ScanResult): void {
  const marginX = doc.page.margins.left;
  const contentWidth = doc.page.width - marginX * 2;

  doc.fontSize(22).fillColor(TEXT_COLOR).text("vibe-audit security report", marginX, doc.page.margins.top, {
    width: contentWidth,
  });
  doc.moveDown(0.6);

  doc.fontSize(11).fillColor(MUTED_COLOR);
  doc.text(`Target: ${result.meta.target}`, { width: contentWidth });
  doc.text(`Mode: ${result.meta.mode}`, { width: contentWidth });
  doc.text(`Generated: ${new Date(result.meta.finishedAt).toLocaleString()}`, { width: contentWidth });
  doc.moveDown(1);

  const gradeColor = GRADE_COLORS[result.grade] ?? TEXT_COLOR;
  doc.fontSize(40).fillColor(gradeColor).text(`Grade: ${result.grade}`, marginX);
  doc.fontSize(14).fillColor(TEXT_COLOR).text(`Score: ${result.score} / 100`, marginX);
  doc.moveDown(1);

  doc.fontSize(13).fillColor(TEXT_COLOR).text("Findings by severity", marginX);
  doc.moveDown(0.4);

  const severities: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const severity of severities) {
    const count = result.countsBySeverity[severity];
    const y = doc.y;
    doc.rect(marginX, y + 2, 10, 10).fill(SEVERITY_COLORS[severity]);
    doc.fillColor(TEXT_COLOR).fontSize(11).text(`${SEVERITY_LABELS[severity]}: ${count}`, marginX + 16, y);
    doc.moveDown(0.5);
  }

  if (result.findings.length === 0) {
    doc.moveDown(0.6);
    doc.fontSize(12).fillColor("#065f46").text("No issues found.", marginX);
  }
}

function renderFinding(doc: PDFKit.PDFDocument, finding: Finding, index: number): void {
  const marginX = doc.page.margins.left;
  const contentWidth = doc.page.width - marginX * 2;

  doc.fontSize(13).fillColor(TEXT_COLOR).text(`${index}. ${finding.title}`, { width: contentWidth });
  doc.fontSize(9).fillColor(SEVERITY_COLORS[finding.severity]).text(SEVERITY_LABELS[finding.severity].toUpperCase());

  const locationSuffix = finding.location
    ? ` · Location: ${finding.location}${finding.line ? `:${finding.line}` : ""}`
    : "";
  doc.fontSize(9).fillColor(MUTED_COLOR).text(`Category: ${finding.category}${locationSuffix}`, {
    width: contentWidth,
  });
  doc.moveDown(0.3);

  doc.fontSize(10).fillColor(TEXT_COLOR).text(finding.description, { width: contentWidth });
  doc.moveDown(0.2);

  if (finding.evidence) {
    doc.fontSize(9).fillColor(MUTED_COLOR).text(`Evidence (masked): ${finding.evidence}`, { width: contentWidth });
    doc.moveDown(0.2);
  }

  if (finding.codeBefore) {
    doc.font("Courier").fontSize(9).fillColor(TEXT_COLOR).text(finding.codeBefore, { width: contentWidth });
    doc.font("Helvetica");
    doc.moveDown(0.2);
  }

  doc.fontSize(10).fillColor("#065f46").text(`Recommendation: ${finding.recommendation}`, { width: contentWidth });
  doc.moveDown(0.5);

  doc
    .moveTo(marginX, doc.y)
    .lineTo(doc.page.width - marginX, doc.y)
    .strokeColor(RULE_COLOR)
    .stroke();
  doc.moveDown(0.5);
}

function renderFindings(doc: PDFKit.PDFDocument, findings: Finding[]): void {
  doc.fontSize(16).fillColor(TEXT_COLOR).text("Findings", doc.page.margins.left, doc.page.margins.top);
  doc.moveDown(0.5);
  findings.forEach((finding, i) => renderFinding(doc, finding, i + 1));
}

/**
 * Renders a PDF report with pdfkit (pure Node.js, no headless browser).
 * Cover page (target, date, score/grade, severity summary) followed by one
 * section per finding, worst severity first. Never receives raw secrets:
 * every Finding.evidence value is expected to already be masked by the
 * scanner that produced it.
 */
export async function generatePdfReport(result: ScanResult): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 50, bufferPages: true });
    const chunks: Buffer[] = [];
    doc.on("data", (chunk: Buffer) => chunks.push(chunk));
    doc.on("end", () => resolve(Buffer.concat(chunks)));
    doc.on("error", reject);

    renderCoverPage(doc, result);

    if (result.findings.length > 0) {
      doc.addPage();
      renderFindings(doc, result.findings);
    }

    doc.end();
  });
}
