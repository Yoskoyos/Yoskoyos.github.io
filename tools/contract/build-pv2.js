// Procese-verbale de intervenție: „garantie” (înlocuire în garanție) și „adaugare” (echipamente adăugate la contract).
// Generează șabloanele: NODE_PATH=... node tools/contract/build-pv2.js garantie|adaugare
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


const KIND = process.argv[2] === 'adaugare' ? 'adaugare' : 'garantie';
const J = { alignment: AlignmentType.JUSTIFIED, spacing: { after: 140, line: 300 } };
const check = (a, b) => P([t('✔  ', { bold: true, color: ORANGE }), t(a, { size: 22 }), ...(b ? [t(b, { bold: true, size: 22 })] : []), t('.', { size: 22 })], { spacing: { after: 90, line: 300 }, indent: { left: 360 } });
const ROWS = 'ABCDEFGH'.split('');
const title = KIND === 'garantie' ? 'PROCES-VERBAL DE ÎNLOCUIRE ÎN GARANȚIE' : 'PROCES-VERBAL DE COMPLETARE A SISTEMULUI';
const tbl = KIND === 'garantie'
  ? table([650, 2700, 1975, 2700, 1500], ['Nr.', 'Echipament defect scos (model, serie)', 'Defect constatat', 'Echipament montat (model, serie)', 'Loc / canal'],
      ROWS.map(r => ['{{M_' + r + '_NR}}', '{{M_' + r + '_OUT}}', '{{M_' + r + '_DEF}}', '{{M_' + r + '_IN}}', '{{M_' + r + '_LOC}}']), { align: [AlignmentType.CENTER] })
  : table([650, 3050, 2925, 900, 2000], ['Nr.', 'Echipament', 'Model și serie', 'Cant.', 'Loc de montaj'],
      ROWS.map(r => ['{{M_' + r + '_NR}}', '{{M_' + r + '_IN}}', '{{M_' + r + '_SER}}', '{{M_' + r + '_QTY}}', '{{M_' + r + '_LOC}}']), { align: [AlignmentType.CENTER, null, null, AlignmentType.CENTER] });
const body = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 }, children: [t(title, { bold: true, size: 30, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 280 }, children: [t('Nr. {{NR}}  din  {{DATA}}', { color: '52606F' })] }),
  P([t('YCA SOLUTIONS S.R.L.', { bold: true }), t(', cu sediul în București, Str. Aviator Mircea Petre nr. 10, Camera 1, Sector 1, CUI 45211628, J2021019754409, reprezentată prin Dima Florin, în calitate de Administrator, denumită în continuare '), t('PRESTATOR', { bold: true }), t(',')], J),
  P('și', J),
  P([t('{{BENEF}}', { bold: true }), t(', cu sediul în {{SEDIU}}, CIF {{CIF}}, reprezentată prin {{REPR}}, în calitate de {{CALIT}}, denumită în continuare '), t('BENEFICIAR', { bold: true }), t(',')], J),
  P(KIND === 'garantie'
    ? 'în baza contractului nr. {{CONTRACT}}, constatăm că la adresa {{IMOBIL}} următoarele echipamente ale sistemului de supraveghere video s-au defectat în perioada de garanție și au fost înlocuite de Prestator, fără costuri pentru Beneficiar:'
    : 'în baza contractului nr. {{CONTRACT}}, constatăm că la adresa {{IMOBIL}} Prestatorul a montat și a pus în funcțiune următoarele echipamente, care se adaugă la sistemul de supraveghere video din contract:', { ...J, spacing: { after: 200, line: 300 } }),
  tbl,
  P('După intervenție s-a verificat, în prezența ambelor părți, că:', { spacing: { before: 260, after: 110, line: 300 } }),
  ...(KIND === 'garantie'
    ? [check('echipamentele montate funcționează și ', 'înregistrează'), check('restul sistemului (camere, NVR, hard disk) funcționează și ', 'înregistrează')]
    : [check('echipamentele adăugate funcționează și ', 'înregistrează'), check('restul sistemului (camere, NVR, hard disk) funcționează și ', 'înregistrează')]),
  P(KIND === 'garantie'
    ? 'Echipamentele defecte au fost preluate de Prestator. Echipamentele montate în locul lor beneficiază de garanție în aceleași condiții ca echipamentele înlocuite, conform contractului. {{M_HDDNOTE}}'
    : 'Echipamentele adăugate fac parte din sistemul de supraveghere video și beneficiază de garanție și mentenanță în aceleași condiții ca restul sistemului, pe durata contractului. {{M_ABON}}', { ...J, spacing: { before: 200, after: 140, line: 300 } }),
  P([t('Observații: ', { bold: true }), t('{{OBS}}')], J),
  P('Prezentul proces-verbal s-a încheiat în 2 exemplare, câte unul pentru fiecare parte.', J),
  new Table({ width: { size: 9525, type: WidthType.DXA }, columnWidths: [4762, 4763], borders: { top: NONE, bottom: NONE, left: NONE, right: NONE, insideHorizontal: NONE, insideVertical: NONE },
    rows: [new TableRow({ cantSplit: true, children: [
      new TableCell({ width: { size: 4762, type: WidthType.DXA }, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE }, margins: { top: 240 }, children: [
        new Paragraph({ children: [t('PRESTATOR', { bold: true, color: NAVY })] }),
        new Paragraph({ children: [t('YCA SOLUTIONS S.R.L.')] }),
        new Paragraph({ children: [t('Administrator: Dima Florin')] }),
        new Paragraph({ spacing: { before: 360 }, children: [t('{{STAMPILA}}'), t('Semnătura și ștampila: ………………………')] }),
      ] }),
      new TableCell({ width: { size: 4763, type: WidthType.DXA }, borders: { top: NONE, bottom: NONE, left: NONE, right: NONE }, margins: { top: 240 }, children: [
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
Packer.toBuffer(doc).then(b => { const out = process.argv[3] || __dirname + '/../../pv-' + KIND + '-template.docx'; fs.writeFileSync(out, b); console.log('ok', out); });
