const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  LevelFormat, PageBreak, Footer, Header, PageNumber, TabStopType, ImageRun } = require('docx');

const F = 'Calibri';
const B = '……………………';
const TPL = process.argv[2] === 'tpl';
const K = n => TPL ? '{{' + n + '}}' : '……………………';

const t = (text, o = {}) => new TextRun({ text, font: F, size: 22, language: { value: 'ro-RO' }, ...o });
const P = (runs, o = {}) => new Paragraph({ children: Array.isArray(runs) ? runs : [t(runs)], spacing: { after: 100, line: 276 }, alignment: AlignmentType.JUSTIFIED, ...o });
const H = text => new Paragraph({ children: [t(text, { bold: true, size: 23 })], spacing: { before: 260, after: 120 }, keepNext: true });
const ART = (n, text, extra = []) => P([t(`Art. ${n}. `, { bold: true }), t(text), ...extra]);
const LI = (text, ref = 'lit') => new Paragraph({ children: Array.isArray(text) ? text : [t(text)], numbering: { reference: ref, level: 0 }, spacing: { after: 70, line: 276 }, alignment: AlignmentType.JUSTIFIED });
let litN = 0; const lits = [];
function L(items) { const ref = 'lit' + (litN++); lits.push(ref); return items.map(x => LI(x, ref)); }

const border = { style: BorderStyle.SINGLE, size: 4, color: '999999' };
const borders = { top: border, bottom: border, left: border, right: border };
function cell(text, w, o = {}) {
  return new TableCell({ borders, width: { size: w, type: WidthType.DXA }, margins: { top: 60, bottom: 60, left: 100, right: 100 },
    shading: o.head ? { fill: 'E8EDF3', type: ShadingType.CLEAR, color: 'auto' } : undefined,
    children: [new Paragraph({ children: [t(text, { bold: !!o.head, size: 20 })] })] });
}
function table(widths, head, rows) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({ width: { size: total, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: head.map((h, i) => cell(h, widths[i], { head: true })) }),
           ...rows.map(r => new TableRow({ children: r.map((c, i) => cell(c, widths[i])) }))] });
}
const sign = (left, right) => [
  new Paragraph({ keepNext: true, keepLines: true, spacing: { before: 400 }, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t('FURNIZOR', { bold: true }), t('\t'), t('BENEFICIAR', { bold: true })] }),
  new Paragraph({ keepNext: true, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t(left[0]), t('\t'), t(right[0])] }),
  new Paragraph({ keepNext: true, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t(left[1]), t('\t'), t(right[1])] }),
  new Paragraph({ spacing: { before: 360 }, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t('Semnătura: ____________________'), t('\t'), t('Semnătura: ____________________')] }),
];


const LOGO = fs.readFileSync(__dirname + '/logo-antet.png');
const hr = (text, o = {}) => new TextRun({ text, font: F, size: 15, color: '52606F', language: { value: 'ro-RO' }, ...o });
const header = new Header({ children: [
  new Table({ width: { size: 9525, type: WidthType.DXA }, columnWidths: [3700, 5825],
    borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.SINGLE, size: 12, color: 'F5A100' }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE }, insideHorizontal: { style: BorderStyle.NONE }, insideVertical: { style: BorderStyle.NONE } },
    rows: [new TableRow({ children: [
      new TableCell({ width: { size: 3700, type: WidthType.DXA }, borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.SINGLE, size: 12, color: 'F5A100' }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } }, margins: { bottom: 100 },
        children: [new Paragraph({ children: [new ImageRun({ type: 'png', data: LOGO, transformation: { width: 205, height: 50 } })] })] }),
      new TableCell({ width: { size: 5825, type: WidthType.DXA }, borders: { top: { style: BorderStyle.NONE }, bottom: { style: BorderStyle.SINGLE, size: 12, color: 'F5A100' }, left: { style: BorderStyle.NONE }, right: { style: BorderStyle.NONE } }, margins: { bottom: 100 },
        children: [
          new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('YCA SOLUTIONS S.R.L.', { bold: true, color: '0D1F33', size: 17 })] }),
          new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('CUI 45211628 · J40/19754/2021')] }),
          new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('Str. Aviator Mircea Petre nr. 10, Sector 1, București')] }),
          new Paragraph({ alignment: AlignmentType.RIGHT, children: [hr('0763 354 355 · contact@supraveghere24h.ro · supraveghere24h.ro')] }),
        ] }),
    ] })] }),
] });

const body = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('CONTRACT DE FURNIZARE ȘI MENTENANȚĂ', { bold: true, size: 30 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('A UNUI SISTEM DE SUPRAVEGHERE VIDEO', { bold: true, size: 30 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 280 }, children: [t(`Nr. ${K('NR')} din ${K('DATA')}`)] }),

  H('I. PĂRȚILE CONTRACTANTE'),
  P([t('YCA SOLUTIONS S.R.L.', { bold: true }), t(', cu sediul social în București, Str. Aviator Mircea Petre nr. 10, Camera 1, Sector 1, înregistrată la Registrul Comerțului sub nr. J40/19754/2021, CUI 45211628, cont bancar RO62INGB0000999911979489 deschis la ING Bank, titulară a licenței de funcționare emise de Inspectoratul General al Poliției Române nr. ' + K('LICENTA') + ', reprezentată prin dl. Dima Florin, în calitate de Administrator, denumită în continuare '), t('FURNIZOR', { bold: true }), t(',')]),
  P('și'),
  P([t('ASOCIAȚIA DE PROPRIETARI ' + K('ASOC'), { bold: true }), t(`, cu sediul în ${K('SEDIU')}, CIF ${K('CIF')}, cont bancar ${K('IBAN')} deschis la ${K('BANCA')}, reprezentată prin ${K('PRES')}, în calitate de Președinte, împuternicit(ă) prin Hotărârea Adunării Generale a Asociației nr. ${K('HAG_NR')} din ${K('HAG_DATA')}, denumită în continuare `), t('BENEFICIAR', { bold: true }), t('.')]),

  H('II. OBIECTUL CONTRACTULUI'),
  ART(1, `Obiectul contractului îl constituie furnizarea, instalarea, punerea în funcțiune și mentenanța unui sistem de supraveghere video la imobilul Beneficiarului din ${K('IMOBIL')} (denumit în continuare „Sistemul”), pe bază de abonament lunar.`),
  ART(2, 'Componența Sistemului (echipamente, modele, cantități, serii și amplasarea camerelor) este prevăzută în Anexa 1, care face parte integrantă din prezentul contract. Orice modificare a componenței se face prin act adițional sau prin actualizarea Anexei 1, semnată de ambele părți.'),

  H('III. DURATA CONTRACTULUI'),
  ART(3, 'Contractul se încheie pe o perioadă de 48 (patruzeci și opt) de luni, începând cu data semnării procesului-verbal de punere în funcțiune a Sistemului.'),
  ART(4, 'Contractul poate fi modificat numai prin act adițional semnat de ambele părți.'),
  ART(5, 'La încheierea perioadei de 48 de luni, părțile pot conveni continuarea serviciului de mentenanță prin act adițional, în condițiile stabilite atunci.'),

  H('IV. PREȚUL ȘI MODALITATEA DE PLATĂ'),
  ART(6, `Prețul abonamentului este de ${K('PRET')} lei pe lună. Prețul acoperă echipamentele, instalarea, punerea în funcțiune, instruirea și mentenanța Sistemului pe toată durata contractului și rămâne fix pe întreaga durată a acestuia. Furnizorul nu este înregistrat în scopuri de TVA, prin urmare prețul nu conține TVA.`),
  ART(7, 'Furnizorul emite lunar factura, iar Beneficiarul o achită prin transfer bancar în contul Furnizorului până la data de 15 a lunii în care a fost emisă factura. Prima factură se emite după semnarea procesului-verbal de punere în funcțiune.'),
  ART(8, 'Pentru plata cu întârziere, Beneficiarul datorează penalități de 0,1% pentru fiecare zi de întârziere, calculate asupra sumei neachitate. Totalul penalităților nu poate depăși valoarea sumei asupra căreia sunt calculate.'),

  H('V. PROPRIETATEA ASUPRA ECHIPAMENTELOR'),
  ART(9, 'Pe durata contractului, echipamentele din Anexa 1 rămân în proprietatea Furnizorului și sunt puse la dispoziția Beneficiarului pentru folosință. Beneficiarul nu le poate înstrăina, greva sau muta fără acordul scris al Furnizorului.'),
  ART(10, 'La încheierea perioadei de 48 de luni, cu condiția achitării integrale a tuturor sumelor datorate, dreptul de proprietate asupra echipamentelor din Anexa 1 se transferă Beneficiarului, fără alte costuri, pe bază de proces-verbal de predare-primire.'),

  H('VI. OBLIGAȚIILE FURNIZORULUI'),
  ART(11, 'Furnizorul se obligă:'),
  ...L([
    'să instaleze și să pună în funcțiune Sistemul în termen de 15 zile lucrătoare de la semnarea contractului, cu respectarea Legii nr. 333/2003 și a normelor de aplicare;',
    'să întocmească procesul-verbal de punere în funcțiune și să instruiască persoanele desemnate de Beneficiar cu privire la utilizarea Sistemului;',
    'să configureze înregistrarea imaginilor pe echipamentul din imobil, cu o durată de păstrare de cel mult 30 de zile, dacă Beneficiarul nu solicită în scris altă durată permisă de lege;',
    'să asigure mentenanța Sistemului pe cheltuiala proprie, pe toată durata contractului, inclusiv actualizarea software a echipamentelor atunci când producătorul publică versiuni noi;',
    'să monitorizeze automat funcționarea Sistemului (starea recorderului, a camerelor, a hard disk-ului și a înregistrării) și să intervină din proprie inițiativă atunci când constată o defecțiune;',
    'să intervină pentru remedierea oricărei defecțiuni în cel mult 48 de ore lucrătoare de la constatare sau de la sesizarea Beneficiarului și să înlocuiască echipamentele defecte în cel mult 5 zile lucrătoare;',
    'să înlocuiască pe cheltuiala proprie, fără limită de evenimente, echipamentele furate sau distruse prin acte de vandalism pe toată durata contractului. Fac excepție deteriorările produse cu intenție sau din culpa gravă a Beneficiarului, caz în care costul echipamentelor se suportă de Beneficiar, pe baza unei oferte acceptate de acesta;',
    'să respecte obligațiile privind protecția datelor personale prevăzute în Anexa 2.',
  ]),
  ART(12, 'Furnizorul nu răspunde pentru întreruperile cauzate de lipsa sau fluctuațiile tensiunii de alimentare, de lucrările efectuate de terți în imobil, de calamități naturale sau de alte cauze aflate în afara controlului său.'),

  H('VII. OBLIGAȚIILE BENEFICIARULUI'),
  ART(13, 'Beneficiarul se obligă:'),
  ...L([
    'să achite la termen abonamentul lunar;',
    'să asigure accesul personalului Furnizorului în imobil pentru instalare, mentenanță și intervenții, inclusiv în spațiile tehnice;',
    'să asigure alimentarea cu energie electrică a Sistemului și un spațiu adecvat pentru montarea rack-ului cu echipamente. Consumul de energie electrică al Sistemului este suportat de Beneficiar;',
    'să sesizeze Furnizorului orice defecțiune la telefon 0763 354 355 sau prin e-mail la contact@supraveghere24h.ro;',
    'să anunțe Furnizorul despre orice lucrare sau modificare la imobil care poate afecta funcționarea Sistemului;',
    'să nu modifice, să nu mute și să nu deterioreze echipamentele și să nu permită intervenția unor terți asupra Sistemului;',
    'să semneze procesele-verbale de punere în funcțiune și de predare-primire;',
    'să își îndeplinească obligațiile de operator de date personale prevăzute în Anexa 2, inclusiv afișarea semnelor de informare privind supravegherea video.',
  ]),

  H('VIII. PROTECȚIA DATELOR PERSONALE'),
  ART(14, 'În raport cu imaginile înregistrate, Beneficiarul are calitatea de operator, iar Furnizorul are calitatea de persoană împuternicită, în sensul Regulamentului (UE) 2016/679 (GDPR). Drepturile și obligațiile părților în această privință sunt prevăzute în Anexa 2.'),
  ART(15, 'Furnizorul păstrează confidențialitatea datelor Beneficiarului și ale locatarilor și nu le face publice, cu excepția cazurilor prevăzute de lege sau acceptate în scris de Beneficiar.'),

  H('IX. ÎNCETAREA CONTRACTULUI'),
  ART(16, 'Contractul încetează:'),
  ...L([
    'la expirarea perioadei de 48 de luni, cu transferul proprietății echipamentelor în condițiile art. 10;',
    'prin acordul scris al părților;',
    'prin reziliere, în condițiile art. 17–19.',
  ]),
  ART(17, 'Dacă Beneficiarul nu achită două facturi consecutive, Furnizorul poate suspenda serviciile de mentenanță și intervenție după o notificare scrisă de 10 zile. Dacă restanța depășește 60 de zile, Furnizorul poate rezilia contractul printr-o notificare scrisă, fără intervenția instanței, și poate ridica echipamentele din Anexa 1.'),
  ART(18, 'Beneficiarul poate denunța contractul înainte de expirarea celor 48 de luni cu o notificare scrisă de 30 de zile. În acest caz, precum și în cazul rezilierii conform art. 17, Beneficiarul datorează, pe lângă sumele scadente, valoarea neamortizată a Sistemului, calculată astfel: valoarea Sistemului din Anexa 1 × numărul de luni rămase până la 48 / 48. După plata acestei sume, echipamentele trec în proprietatea Beneficiarului. Alternativ, dacă părțile convin în scris, Beneficiarul poate preda echipamentele în stare de funcționare, caz în care datorează numai sumele scadente și costul demontării.'),
  ART(19, 'Beneficiarul poate rezilia contractul dacă Furnizorul nu remediază o defecțiune în termenele prevăzute la art. 11, deși a fost notificat în scris și i s-a acordat un termen suplimentar de 15 zile. În acest caz, art. 18 nu se aplică, iar Beneficiarul achită numai sumele scadente.'),
  ART(20, 'Încetarea contractului nu afectează obligațiile scadente ale părților.'),

  H('X. FORȚA MAJORĂ'),
  ART(21, 'Forța majoră exonerează de răspundere partea care o invocă, în condițiile legii. Partea care invocă forța majoră o notifică celeilalte părți în cel mult 5 zile de la apariție și transmite dovezile corespunzătoare. Dacă forța majoră durează mai mult de 30 de zile, părțile se întâlnesc pentru a decide continuarea sau încetarea contractului.'),

  H('XI. COMUNICĂRI'),
  ART(22, 'Comunicările între părți se fac în scris, la adresele de mai sus sau prin e-mail, la adresele: Furnizor: contact@supraveghere24h.ro; Beneficiar: ' + K('EMAIL') + '. Sesizările de defecțiuni se pot face și telefonic.'),

  H('XII. LITIGII'),
  ART(23, 'Litigiile care nu pot fi soluționate pe cale amiabilă se soluționează de instanțele competente de la sediul Furnizorului.'),

  H('XIII. DISPOZIȚII FINALE'),
  ART(24, 'Anexele 1 și 2 fac parte integrantă din prezentul contract.'),
  new Paragraph({ keepNext: true, spacing: { after: 100, line: 276 }, alignment: AlignmentType.JUSTIFIED, children: [t('Art. 25. ', { bold: true }), t(`Contractul a fost încheiat astăzi, ${K('DATA')}, în două exemplare originale, câte unul pentru fiecare parte.`)] }),
  ...sign(['YCA SOLUTIONS S.R.L.', 'Administrator, Dima Florin'], ['ASOCIAȚIA DE PROPRIETARI ' + K('ASOC'), 'Președinte, ' + K('PRES')]),

  // ── Anexa 1
  new Paragraph({ children: [new PageBreak()] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('ANEXA 1', { bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [t(`la contractul nr. ${K('NR')} din ${K('DATA')} — Componența Sistemului`, { size: 22 })] }),
  table([500, 3300, 2400, 2000, 826], ['Nr.', 'Echipament', 'Model', 'Serie', 'Cant.'], [
    ['1', 'Recorder video în rețea (NVR)', TPL ? '{{M_NVR}}' : '', '', '1'],
    ['2', 'Hard disk pentru înregistrare', TPL ? '{{M_HDD}}' : '', '', TPL ? '{{Q_HDD}}' : ''],
    ['3', 'Camere IP exterior', TPL ? '{{M_EXT}}' : '', '', TPL ? '{{Q_EXT}}' : ''],
    ['4', 'Camere IP interior', TPL ? '{{M_INT}}' : '', '', TPL ? '{{Q_INT}}' : ''],
    ['5', 'Camere lift', TPL ? '{{M_LIFT}}' : '', '', TPL ? '{{Q_LIFT}}' : ''],
    ['6', 'Switch PoE', '', '', ''],
    ['7', 'Rack metalic cu yală', TPL ? '{{M_RACK}}' : '', '', '1'],
    ['8', 'Monitor', '', '', TPL ? '{{Q_MON}}' : ''],
    ['9', 'Materiale de instalare (cablu, doze, pat de cablu, conectori)', '—', '—', '—'],
  ]),
  P([t('Amplasarea camerelor: ', { bold: true }), t(K('AMPLASARE'))], { spacing: { before: 200, after: 100 } }),
  P([t('Valoarea Sistemului (echipamente, materiale și manoperă), folosită pentru calculul de la art. 18: ', { bold: true }), t(`${K('VALOARE')} lei.`)]),
  ...sign(['YCA SOLUTIONS S.R.L.', 'Administrator, Dima Florin'], ['ASOCIAȚIA DE PROPRIETARI ' + K('ASOC'), 'Președinte, ' + K('PRES')]),

  // ── Anexa 2
  new Paragraph({ children: [new PageBreak()] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('ANEXA 2', { bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [t(`la contractul nr. ${K('NR')} din ${K('DATA')} — Acord privind prelucrarea datelor personale (art. 28 GDPR)`, { size: 22 })] }),
  P([t('1. Obiect. ', { bold: true }), t('Prin funcționarea Sistemului se prelucrează imagini video ale persoanelor din imobil și din zonele supravegheate. Beneficiarul este operator, iar Furnizorul este persoană împuternicită și prelucrează datele numai în măsura necesară instalării, mentenanței și remedierii Sistemului, pe durata contractului.')]),
  P([t('2. Obligațiile Furnizorului. ', { bold: true }), t('Furnizorul se obligă:')]),
  ...L([
    'să acceseze imaginile, local sau de la distanță, numai pentru verificarea funcționării Sistemului, la solicitarea Beneficiarului sau atunci când este strict necesar pentru remedierea unei defecțiuni;',
    'să nu copieze, să nu păstreze și să nu transmită imagini către terți, cu excepția cazurilor în care primește instrucțiuni scrise de la Beneficiar sau o solicitare legală a unei autorități, despre care informează Beneficiarul, dacă legea permite;',
    'să asigure confidențialitatea persoanelor care au acces la Sistem din partea sa și să le instruiască în acest sens;',
    'să aplice măsuri tehnice de securitate adecvate: parole puternice și individuale, actualizarea software a echipamentelor, acces de la distanță numai prin conexiuni securizate;',
    'să notifice Beneficiarului, fără întârzieri nejustificate și în cel mult 48 de ore de la constatare, orice incident de securitate care afectează imaginile;',
    'să îl ajute pe Beneficiar, în măsura posibilului, să răspundă cererilor persoanelor vizate și ale autorităților;',
    'să nu recurgă la alți împuterniciți fără acordul scris al Beneficiarului;',
    'la încetarea contractului, să predea Beneficiarului datele de acces la Sistem și să nu păstreze copii ale imaginilor.',
  ]),
  P([t('3. Obligațiile Beneficiarului. ', { bold: true }), t('Beneficiarul, în calitate de operator, răspunde de:')]),
  ...L([
    'stabilirea scopului supravegherii (siguranța persoanelor și a bunurilor) și aprobarea instalării prin hotărâre a adunării generale;',
    'afișarea, la vedere, a semnelor de informare privind supravegherea video și informarea locatarilor;',
    'desemnarea în scris a persoanelor care au acces la imagini și ținerea evidenței accesărilor și a cererilor de imagini;',
    'stabilirea duratei de păstrare a imaginilor, de regulă cel mult 30 de zile;',
    'evitarea filmării spațiilor private (interiorul locuințelor, ușile apartamentelor din unghiuri care permit vederea în interior).',
  ]),
  P([t('4. ', { bold: true }), t('Prezenta anexă se aplică pe toată durata contractului și se completează cu prevederile Regulamentului (UE) 2016/679 și ale Legii nr. 190/2018.')]),
  ...sign(['YCA SOLUTIONS S.R.L.', 'Administrator, Dima Florin'], ['ASOCIAȚIA DE PROPRIETARI ' + K('ASOC'), 'Președinte, ' + K('PRES')]),
];

const doc = new Document({
  creator: 'YCA SOLUTIONS S.R.L.', title: 'Contract de furnizare și mentenanță sistem de supraveghere video',
  styles: { default: { document: { run: { font: F, size: 22, language: { value: 'ro-RO' } } } } },
  numbering: { config: lits.map(ref => ({ reference: ref, levels: [{ level: 0, format: LevelFormat.LOWER_LETTER, text: '%1)', alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: 567, hanging: 340 } } } }] })) },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1700, bottom: 1134, left: 1247, right: 1134, header: 500 } } },
    headers: { default: header },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t('Pagina ', { size: 18, color: '777777' }), new TextRun({ children: [PageNumber.CURRENT], font: F, size: 18, color: '777777' }), t(' din ', { size: 18, color: '777777' }), new TextRun({ children: [PageNumber.TOTAL_PAGES], font: F, size: 18, color: '777777' })] })] }) },
    children: body }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(__dirname + (TPL ? '/contract-template.docx' : '/Contract_supraveghere_video_YCA.docx'), b); console.log('ok'); });
