// Act adițional la contract: echipamente adăugate + abonament nou. Generează: NODE_PATH=... node tools/contract/build-aa.js [ieșire]
const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  Footer, Header, ImageRun, VerticalAlign, TabStopType } = require('docx');

const F = 'Calibri', NAVY = '0D1F33', ORANGE = 'F5A100';
const TPL = true;
const K = (n, blank) => TPL ? '{{' + n + '}}' : blank;
const t = (text, o = {}) => new TextRun({ text, font: F, size: 21, language: { value: 'ro-RO' }, ...o });
const P = (runs, o = {}) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], spacing: { after: 70, line: 260 }, ...o });
const H = text => new Paragraph({ keepNext: true, spacing: { before: 170, after: 90 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: ORANGE, space: 2 } },
  children: [t(text, { bold: true, size: 22, color: NAVY })] });
const line = '…………………………………………';
const NONE = { style: BorderStyle.NONE, size: 0, color: 'FFFFFF' };
const grid = { style: BorderStyle.SINGLE, size: 4, color: 'B8C2CE' };
const gb = { top: grid, bottom: grid, left: grid, right: grid };
function cell(content, w, o = {}) {
  const kids = (Array.isArray(content) ? content : [content]).map(c => typeof c === 'string' ? new Paragraph({ alignment: o.align || AlignmentType.LEFT, children: [t(c, { bold: !!o.head, size: 21, color: o.head ? 'FFFFFF' : undefined })] }) : c);
  return new TableCell({ borders: o.borders || gb, width: { size: w, type: WidthType.DXA }, verticalAlign: VerticalAlign.CENTER,
    margins: { top: 90, bottom: 90, left: 140, right: 140 },
    shading: o.head ? { fill: NAVY, type: ShadingType.CLEAR, color: 'auto' } : (o.fill ? { fill: o.fill, type: ShadingType.CLEAR, color: 'auto' } : undefined), children: kids });
}
function table(widths, head, rows, o = {}) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: head.map((h, i) => cell(h, widths[i], { head: true, align: o.align && o.align[i] })) }),
      ...rows.map((r, k) => new TableRow({ children: r.map((c, i) => cell(c, widths[i], { size: 22, fill: k % 2 ? 'F4F6F9' : undefined, align: o.align && o.align[i] })) }))] });
}

const LOGO = fs.readFileSync(__dirname + '/logo-antet.png');
const hr = (text, o = {}) => new TextRun({ text, font: F, size: 15, color: '52606F', language: { value: 'ro-RO' }, ...o });
const hb = { top: NONE, bottom: { style: BorderStyle.SINGLE, size: 12, color: ORANGE }, left: NONE, right: NONE };
const header = new Header({ children: [
  new Table({ width: { size: 9525, type: WidthType.DXA }, columnWidths: [3700, 5825],
    borders: { ...hb, insideHorizontal: NONE, insideVertical: NONE },
    rows: [new TableRow({ children: [
      new TableCell({ width: { size: 3700, type: WidthType.DXA }, borders: hb, margins: { bottom: 100 },
        children: [new Paragraph({ children: [new ImageRun({ type: 'png', data: LOGO, transformation: { width: 205, height: 50 } })] })] }),
      new TableCell({ width: { size: 5825, type: WidthType.DXA }, borders: hb, margins: { bottom: 100 }, children: [
        new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('YCA SOLUTIONS S.R.L.', { bold: true, color: NAVY, size: 17 })] }),
        new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('CUI 45211628 · J2021019754409 · Licență IGPR nr. 6310/T')] }),
        new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('Str. Aviator Mircea Petre nr. 10, Camera 1, Sector 1, București')] }),
        new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('0763 354 355 · contact@supraveghere24h.ro · supraveghere24h.ro')] }),
      ] }),
    ] })] }),
] });


const J = { alignment: AlignmentType.JUSTIFIED, spacing: { after: 140, line: 300 } };
const title = 'ACT ADIȚIONAL';
const art = (n, runs) => P([t('Art. ' + n + '. ', { bold: true }), ...runs], J);
const body = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 40 }, children: [t('ACT ADIȚIONAL nr. {{NR}}', { bold: true, size: 30, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 280 }, children: [t('la contractul nr. {{CONTRACT}}  ·  încheiat astăzi, {{DATA}}', { color: '52606F' })] }),
  P([t('YCA SOLUTIONS S.R.L.', { bold: true }), t(', cu sediul în București, Str. Aviator Mircea Petre nr. 10, Camera 1, Sector 1, CUI 45211628, J2021019754409, reprezentată prin Dima Florin, în calitate de Administrator, denumită în continuare '), t('PRESTATOR', { bold: true }), t(',')], J),
  P('și', J),
  P([t('{{BENEF}}', { bold: true }), t(', cu sediul în {{SEDIU}}, CIF {{CIF}}, reprezentată prin {{REPR}}, în calitate de {{CALIT}}, denumită în continuare '), t('BENEFICIAR', { bold: true }), t(',')], J),
  P('au convenit modificarea contractului, după cum urmează:', { ...J, spacing: { after: 200, line: 300 } }),
  art(1, [t('Sistemul de supraveghere video de la adresa {{IMOBIL}} se completează cu următoarele echipamente, montate și puse în funcțiune conform procesului-verbal de completare nr. {{PV_NR}} din {{DATA}}: '), t('{{ECHIP}}', { bold: true }), t('.')]),
  art(2, [t('Începând cu '), t('{{FROM}}', { bold: true }), t(', abonamentul lunar se modifică de la {{ABON_VECHI}} lei la '), t('{{ABON_NOU}} lei / lună', { bold: true }), t(' (o creștere de {{DIFF}} lei / lună). Termenele și modalitatea de plată rămân cele din contract.')]),
  art(3, [t('Echipamentele adăugate beneficiază de garanție, mentenanță și service în aceleași condiții ca restul sistemului, pe toată durata contractului.')]),
  art(4, [t('Celelalte prevederi ale contractului rămân neschimbate. Prezentul act adițional face parte integrantă din contract și s-a încheiat în 2 exemplare originale, câte unul pentru fiecare parte.')]),
  new Table({ width: { size: 9525, type: WidthType.DXA }, columnWidths: [4762, 4763], borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    rows: [new TableRow({ cantSplit: true, children: [
      new TableCell({ width: { size: 4762, type: WidthType.DXA }, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE }, margins: { top: 360 }, children: [
        new Paragraph({ children: [t('PRESTATOR', { bold: true, color: NAVY })] }),
        new Paragraph({ children: [t('YCA SOLUTIONS S.R.L.')] }),
        new Paragraph({ children: [t('Administrator: Dima Florin')] }),
        new Paragraph({ spacing: { before: 360 }, children: [t('{{STAMPILA}}'), t('Semnătura și ștampila: ………………………')] }),
      ] }),
      new TableCell({ width: { size: 4763, type: WidthType.DXA }, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE }, margins: { top: 360 }, children: [
        new Paragraph({ children: [t('BENEFICIAR', { bold: true, color: NAVY })] }),
        new Paragraph({ children: [t('{{BENEF}}')] }),
        new Paragraph({ children: [t('{{CALIT}}: {{REPR}}')] }),
        new Paragraph({ spacing: { before: 360 }, children: [t('Semnătura și ștampila: ………………………')] }),
      ] }),
    ] })] }),
];
const doc = new Document({
  creator: 'YCA SOLUTIONS S.R.L.', title,
  styles: { default: { document: { run: { font: F, size: 21, language: { value: 'ro-RO' } } } } },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1560, bottom: 700, left: 1247, right: 1134, header: 450, footer: 400 } } },
    headers: { default: header },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t('SUPRAVEGHERE24h · securitate rezidențială non-stop · supraveghere24h.ro', { size: 15, color: '8A97A6' })] })] }) },
    children: body }],
});
Packer.toBuffer(doc).then(b => { const out = process.argv[2] || __dirname + '/../../act-aditional-template.docx'; fs.writeFileSync(out, b); console.log('ok', out); });
