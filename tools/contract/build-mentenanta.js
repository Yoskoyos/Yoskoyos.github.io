const fs = require('fs');
const { Document, Packer, Paragraph, TextRun, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType,
  LevelFormat, PageBreak, Footer, Header, PageNumber, TabStopType, ImageRun } = require('docx');

const F = 'Calibri';
const B = '……………………';
const TPL = process.argv[2] === 'tpl';
const DEF = { VIZITE: 'o dată la 3 luni', START: '……………………' };
const K = n => TPL ? '{{' + n + '}}' : (DEF[n] || '……………………');

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
  new Paragraph({ keepNext: true, keepLines: true, spacing: { before: 400 }, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t('PRESTATOR', { bold: true }), t('\t'), t('BENEFICIAR', { bold: true })] }),
  new Paragraph({ keepNext: true, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t(left[0]), t('\t'), t(right[0])] }),
  new Paragraph({ keepNext: true, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [t(left[1]), t('\t'), t(right[1])] }),
  // {{STAMPILA}}: aplicația pune aici ștampila (imagine plutitoare peste semnătură), doar pentru utilizatorul logat
  new Paragraph({ spacing: { before: 360 }, tabStops: [{ type: TabStopType.LEFT, position: 5200 }], children: [...(TPL ? [t('{{STAMPILA}}')] : []), t('Semnătura: ____________________'), t('\t'), t('Semnătura: ____________________')] }),
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


const SIG = () => sign(['YCA SOLUTIONS S.R.L.', 'Administrator, Dima Florin'], [K('BEN'), K('REP_FUNCTIE') + ', ' + K('REP')]);
const body = [
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('CONTRACT DE MENTENANȚĂ', { bold: true, size: 30 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('PENTRU UN SISTEM DE SUPRAVEGHERE VIDEO', { bold: true, size: 30 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 280 }, children: [t(`Nr. ${K('NR')} din ${K('DATA')}`)] }),

  H('I. PĂRȚILE CONTRACTANTE'),
  P([t('YCA SOLUTIONS S.R.L.', { bold: true }), t(', cu sediul social în București, Str. Aviator Mircea Petre nr. 10, Camera 1, Sector 1, înregistrată la Registrul Comerțului sub nr. J40/19754/2021, CUI 45211628, cont bancar RO62INGB0000999911979489 deschis la ING Bank, titulară a licenței de funcționare nr. 6310/T din 14.06.2022 emise de Inspectoratul General al Poliției Române, reprezentată prin dl. Dima Florin, în calitate de Administrator, denumită în continuare '), t('PRESTATOR', { bold: true }), t(',')]),
  P('și'),
  P([t(K('BEN'), { bold: true }), t(`, cu sediul în ${K('SEDIU')}, înregistrată la Registrul Comerțului sub nr. ${K('REGCOM')}, CUI/CIF ${K('CIF')}, cont bancar ${K('IBAN')} deschis la ${K('BANCA')}, reprezentată prin ${K('REP')}, în calitate de ${K('REP_FUNCTIE')}, denumită în continuare `), t('BENEFICIAR', { bold: true }), t('.')]),

  H('II. OBIECTUL CONTRACTULUI'),
  ART(1, `Obiectul contractului îl constituie mentenanța preventivă și corectivă, precum și monitorizarea de la distanță a funcționării sistemului de supraveghere video al Beneficiarului, amplasat la adresa ${K('ADRESA')} (denumit în continuare „Sistemul”).`),
  ART(2, 'Componența Sistemului (echipamente, modele, cantități și amplasarea camerelor) este prevăzută în Anexa 1, care face parte integrantă din prezentul contract. Echipamentele sunt și rămân proprietatea Beneficiarului.'),
  ART(3, 'La începerea contractului, Prestatorul verifică Sistemul și consemnează starea acestuia în Anexa 1. Defecțiunile existente la data preluării nu sunt incluse în prețul mentenanței și se remediază pe baza unei oferte acceptate de Beneficiar.'),

  H('III. DURATA CONTRACTULUI'),
  ART(4, `Contractul se încheie pe o perioadă de 12 (douăsprezece) luni, începând cu data de ${K('START')}.`),
  ART(5, 'La expirare, contractul se prelungește automat pentru perioade succesive de câte 12 luni, dacă niciuna dintre părți nu notifică în scris încetarea cu cel puțin 30 de zile înainte de expirarea perioadei în curs.'),
  ART(6, 'Contractul poate fi modificat numai prin act adițional semnat de ambele părți.'),

  H('IV. SERVICIILE INCLUSE ÎN MENTENANȚĂ'),
  ART(7, 'Prețul lunar al mentenanței include:'),
  ...L([
    [t('vizite de mentenanță preventivă ', { bold: true }), t(`la sediul Beneficiarului, ${K('VIZITE')}, la o dată stabilită de comun acord. La fiecare vizită Prestatorul verifică și, după caz, curăță camerele, verifică orientarea și claritatea imaginii, alimentarea și conexiunile, starea hard disk-urilor și a înregistrării, ora echipamentelor, actualizează software-ul (firmware) atunci când producătorul publică versiuni noi și salvează configurația Sistemului. Constatările se consemnează într-un raport sau proces-verbal transmis Beneficiarului;`)],
    [t('monitorizarea automată de la distanță, 24/7, ', { bold: true }), t('a funcționării recorderului, a camerelor, a hard disk-urilor și a înregistrării, cu anunțarea Beneficiarului atunci când este constatată o defecțiune, cu condiția ca Sistemul să fie conectat la internet;')],
    [t('manopera intervențiilor de remediere ', { bold: true }), t('a defecțiunilor apărute în timpul contractului, inclusiv deplasarea în București și județul Ilfov;')],
    [t('asistență tehnică ', { bold: true }), t('telefonică și de la distanță pentru utilizarea Sistemului, în zilele lucrătoare, între orele 9:00 și 18:00;')],
    [t('căutarea și extragerea înregistrărilor ', { bold: true }), t('la cererea scrisă a Beneficiarului (de exemplu pentru organele de poliție), cu respectarea Anexei 2.')],
  ]),
  ART(8, 'Nu sunt incluse în prețul lunar și se facturează separat, numai pe baza unei oferte acceptate în scris (inclusiv prin e-mail sau mesaj) de Beneficiar:'),
  ...L([
    'piesele de schimb și echipamentele noi (camere, hard disk-uri, surse, switch-uri, recordere etc.), cablurile și materialele;',
    'extinderea Sistemului, mutarea camerelor sau modificarea instalației;',
    'remedierea defecțiunilor produse prin furt, vandalism, intervenția unor persoane neautorizate, supratensiuni, descărcări atmosferice, inundații, incendii sau lucrări efectuate de terți în imobil;',
    'intervențiile solicitate în afara zilelor și orelor lucrătoare, dacă nu sunt cauzate de o defecțiune constatată de monitorizarea Prestatorului.',
  ]),

  H('V. TERMENE DE INTERVENȚIE'),
  ART(9, 'Prestatorul intervine pentru remedierea defecțiunilor în cel mult 48 de ore lucrătoare de la sesizarea scrisă a Beneficiarului (e-mail sau mesaj) ori de la constatarea defecțiunii prin monitorizare. Când remedierea necesită piese de schimb, Prestatorul transmite oferta în același termen, iar remedierea se face în cel mult 5 zile lucrătoare de la acceptarea ofertei, în funcție de disponibilitatea pieselor la furnizori.'),

  H('VI. PREȚUL ȘI MODALITATEA DE PLATĂ'),
  ART(10, `Prețul mentenanței este de ${K('PRET')} lei pe lună. Prestatorul nu este înregistrat în scopuri de TVA, prin urmare prețul nu conține TVA.`),
  ART(11, 'Prestatorul emite factura lunar, în primele 5 zile ale lunii pentru luna în curs, iar Beneficiarul o achită prin transfer bancar în cel mult 15 zile calendaristice de la emitere.'),
  ART(12, 'Pentru plata cu întârziere, Beneficiarul datorează penalități de 0,1% pentru fiecare zi de întârziere, calculate asupra sumei neachitate. Totalul penalităților nu poate depăși valoarea sumei asupra căreia sunt calculate.'),
  ART(13, 'Prețul poate fi modificat numai la prelungirea contractului, cu o notificare scrisă transmisă Beneficiarului cu cel puțin 30 de zile înainte. Dacă Beneficiarul nu acceptă noul preț, poate notifica încetarea contractului la sfârșitul perioadei în curs.'),

  H('VII. OBLIGAȚIILE PRESTATORULUI'),
  ART(14, 'Prestatorul se obligă:'),
  ...L([
    'să presteze serviciile prevăzute la art. 7, în termenele de la art. 9, cu personal instruit și cu respectarea Legii nr. 333/2003 privind paza obiectivelor, bunurilor, valorilor și protecția persoanelor;',
    'să informeze Beneficiarul despre defecțiunile constatate și despre echipamentele care trebuie înlocuite, cu recomandări și ofertă de preț;',
    'să folosească, la înlocuiri, echipamente noi, compatibile cu Sistemul, cu garanția producătorului;',
    'să păstreze parolele și datele de acces la Sistem în siguranță și să nu le comunice terților;',
    'să respecte obligațiile privind protecția datelor personale prevăzute în Anexa 2.',
  ]),

  H('VIII. OBLIGAȚIILE BENEFICIARULUI'),
  ART(15, 'Beneficiarul se obligă:'),
  ...L([
    'să achite la termen prețul mentenanței și, după caz, contravaloarea lucrărilor acceptate conform art. 8;',
    'să asigure accesul personalului Prestatorului la echipamente, inclusiv în spațiile tehnice, pentru vizite și intervenții;',
    'să asigure alimentarea cu energie electrică a Sistemului și, pentru monitorizarea de la distanță, o conexiune la internet. Costurile acestora sunt suportate de Beneficiar;',
    `să desemneze o persoană de contact (${K('CONTACT')}) și să sesizeze defecțiunile la telefon 0763 354 355, prin mesaj sau prin e-mail la contact@supraveghere24h.ro;`,
    'să nu permită intervenția unor terți asupra Sistemului pe durata contractului și să anunțe Prestatorul despre orice lucrare la imobil care poate afecta funcționarea acestuia;',
    'să își îndeplinească obligațiile de operator de date personale prevăzute în Anexa 2, inclusiv afișarea semnelor de informare privind supravegherea video.',
  ]),

  H('IX. RĂSPUNDEREA PĂRȚILOR'),
  ART(16, 'Sistemul de supraveghere video are rol de descurajare și de înregistrare a evenimentelor. Prestatorul nu garantează prevenirea furturilor, a actelor de vandalism sau a altor fapte ale terților și nu răspunde pentru prejudiciile produse de acestea.'),
  ART(17, 'Prestatorul nu răspunde pentru imaginile neînregistrate sau pierdute din cauze aflate în afara controlului său, precum: lipsa tensiunii de alimentare, lipsa conexiunii la internet, defecțiuni nesesizate și neconstatate, intervenția unor terți sau nerespectarea de către Beneficiar a obligațiilor din prezentul contract.'),
  ART(18, 'Cu excepția prejudiciilor cauzate cu intenție sau din culpă gravă, răspunderea totală a Prestatorului în legătură cu prezentul contract este limitată la valoarea a 3 (trei) luni de mentenanță.'),

  H('X. PROTECȚIA DATELOR ȘI CONFIDENȚIALITATE'),
  ART(19, 'În raport cu imaginile înregistrate, Beneficiarul are calitatea de operator, iar Prestatorul are calitatea de persoană împuternicită, în sensul Regulamentului (UE) 2016/679 (GDPR). Drepturile și obligațiile părților în această privință sunt prevăzute în Anexa 2.'),
  ART(20, 'Părțile păstrează confidențialitatea informațiilor primite în executarea contractului, inclusiv a imaginilor, a parolelor și a datelor de acces la Sistem și a datelor persoanelor de contact, cu excepția cazurilor prevăzute de lege sau acceptate în scris de cealaltă parte. Obligația se menține și după încetarea contractului.'),

  H('XI. ÎNCETAREA CONTRACTULUI'),
  ART(21, 'Contractul încetează:'),
  ...L([
    'la expirarea duratei, dacă una dintre părți a notificat încetarea conform art. 5;',
    'prin acordul scris al părților;',
    'prin denunțare unilaterală de către oricare parte, cu o notificare scrisă de 30 de zile;',
    'prin reziliere, în condițiile art. 22 și 23.',
  ]),
  ART(22, 'Dacă Beneficiarul întârzie plata unei facturi mai mult de 30 de zile, Prestatorul poate suspenda serviciile după o notificare scrisă de 5 zile. Dacă întârzierea depășește 60 de zile, Prestatorul poate rezilia contractul printr-o notificare scrisă, fără intervenția instanței.'),
  ART(23, 'Oricare parte poate rezilia contractul dacă cealaltă parte nu își îndeplinește obligațiile, deși a fost notificată în scris și i s-a acordat un termen de 15 zile pentru remediere.'),
  ART(24, 'La încetarea contractului, Prestatorul predă Beneficiarului datele de acces la Sistem. Încetarea nu afectează obligațiile scadente ale părților.'),

  H('XII. FORȚA MAJORĂ'),
  ART(25, 'Forța majoră exonerează de răspundere partea care o invocă, în condițiile legii. Partea care invocă forța majoră o notifică celeilalte părți în cel mult 5 zile de la apariție și transmite dovezile corespunzătoare. Dacă forța majoră durează mai mult de 30 de zile, părțile se întâlnesc pentru a decide continuarea sau încetarea contractului.'),

  H('XIII. COMUNICĂRI'),
  ART(26, `Comunicările între părți se fac în scris, la adresele de mai sus sau prin e-mail: Prestator: contact@supraveghere24h.ro; Beneficiar: ${K('EMAIL')}. Sesizările de defecțiuni se pot face și telefonic sau prin mesaj.`),

  H('XIV. LITIGII'),
  ART(27, 'Litigiile care nu pot fi soluționate pe cale amiabilă se soluționează de instanțele competente de la sediul Prestatorului.'),

  H('XV. DISPOZIȚII FINALE'),
  ART(28, 'Anexele 1 și 2 fac parte integrantă din prezentul contract.'),
  new Paragraph({ keepNext: true, spacing: { after: 100, line: 276 }, alignment: AlignmentType.JUSTIFIED, children: [t('Art. 29. ', { bold: true }), t(`Contractul a fost încheiat astăzi, ${K('DATA')}, în două exemplare originale, câte unul pentru fiecare parte.`)] }),
  ...SIG(),

  // ── Anexa 1
  new Paragraph({ children: [new PageBreak()] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('ANEXA 1', { bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [t(`la contractul nr. ${K('NR')} din ${K('DATA')} — Componența Sistemului și starea la preluare`, { size: 22 })] }),
  table([500, 2900, 2300, 900, 2726], ['Nr.', 'Echipament', 'Model', 'Cant.', 'Stare la preluare'], [
    ['1', 'Recorder video (NVR / DVR)', '', '', ''],
    ['2', 'Hard disk pentru înregistrare', '', '', ''],
    ['3', 'Camere exterior', '', '', ''],
    ['4', 'Camere interior', '', '', ''],
    ['5', 'Switch PoE / surse de alimentare', '', '', ''],
    ['6', 'Monitor', '', '', ''],
    ['7', 'Rack / UPS / alte echipamente', '', '', ''],
  ]),
  P([t('Durata de păstrare a înregistrărilor constatată la preluare: ', { bold: true }), t(K('RETENTIE') + ' zile.')], { spacing: { before: 200, after: 100 } }),
  P([t('Amplasarea camerelor: ', { bold: true }), t(K('AMPLASARE'))]),
  P([t('Defecțiuni constatate la preluare (se remediază conform art. 3): ', { bold: true }), t(K('DEFECTE'))]),
  ...SIG(),

  // ── Anexa 2
  new Paragraph({ children: [new PageBreak()] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 60 }, children: [t('ANEXA 2', { bold: true, size: 26 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 240 }, children: [t(`la contractul nr. ${K('NR')} din ${K('DATA')} — Acord privind prelucrarea datelor personale (art. 28 GDPR)`, { size: 22 })] }),
  P([t('1. Obiect. ', { bold: true }), t('Prin funcționarea Sistemului se prelucrează imagini video ale persoanelor din zonele supravegheate. Beneficiarul este operator, iar Prestatorul este persoană împuternicită și prelucrează datele numai în măsura necesară mentenanței, monitorizării și remedierii Sistemului, pe durata contractului.')]),
  P([t('2. Obligațiile Prestatorului. ', { bold: true }), t('Prestatorul se obligă:')]),
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
    'stabilirea scopului supravegherii și a temeiului legal al prelucrării;',
    'afișarea, la vedere, a semnelor de informare privind supravegherea video și informarea persoanelor vizate (angajați, vizitatori, locatari, după caz);',
    'desemnarea în scris a persoanelor care au acces la imagini și ținerea evidenței accesărilor și a cererilor de imagini;',
    'stabilirea duratei de păstrare a imaginilor, de regulă cel mult 30 de zile;',
    'evitarea filmării spațiilor în care persoanele au o așteptare rezonabilă de intimitate.',
  ]),
  P([t('4. ', { bold: true }), t('Prezenta anexă se aplică pe toată durata contractului și se completează cu prevederile Regulamentului (UE) 2016/679 și ale Legii nr. 190/2018.')]),
  ...SIG(),
];

const doc = new Document({
  creator: 'YCA SOLUTIONS S.R.L.', title: 'Contract de mentenanță sistem de supraveghere video',
  styles: { default: { document: { run: { font: F, size: 22, language: { value: 'ro-RO' } } } } },
  numbering: { config: lits.map(ref => ({ reference: ref, levels: [{ level: 0, format: LevelFormat.LOWER_LETTER, text: '%1)', alignment: AlignmentType.LEFT,
    style: { paragraph: { indent: { left: 567, hanging: 340 } } } }] })) },
  sections: [{ properties: { page: { size: { width: 11906, height: 16838 }, margin: { top: 1700, bottom: 1134, left: 1247, right: 1134, header: 500 } } },
    headers: { default: header },
    footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [t('Pagina ', { size: 18, color: '777777' }), new TextRun({ children: [PageNumber.CURRENT], font: F, size: 18, color: '777777' }), t(' din ', { size: 18, color: '777777' }), new TextRun({ children: [PageNumber.TOTAL_PAGES], font: F, size: 18, color: '777777' })] })] }) },
    children: body }],
});
Packer.toBuffer(doc).then(b => { fs.writeFileSync(__dirname + (TPL ? '/contract-mentenanta-template.docx' : '/Contract_mentenanta_YCA.docx'), b); console.log('ok'); });
