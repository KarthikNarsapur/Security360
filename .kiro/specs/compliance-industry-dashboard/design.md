:etowith 8 pgein,aasectin wthndgpgsTh-spcificpgee.g.W→Bai Sc)remiunchnged — theopraenand single accoun. TCpo3naalll (default: "All Clouds")pgeC without triggering any scansarchtcur followth epat but xteds iwith li-cloudatafecing, unififnralizati layr,dnew `CFilter`poent.A ew`ompianceCnfig.j` mdleralizslaewrk anidusry madata-BasedD-ehancedFDFidingDrweD - extendedETCHfetchAllCloudsReport]
        NORM[ERGEReultsBackend sWS_A cloud=aws/AZ_API/api/get-reprt ud=azue/]
        GCP_API[/pi/t-reportld=gcp/DDID|linksto| DDCDFTCDFDDFETHFETHWS_ETCHAZ_APIETCHGP_AIFETHNORMEH GD CDUCCIDC: Report U as CD asComplancDashod FETCH fetcAllCloudsRept AWS asBkn (AWS)ZBcknd (Azu)
    aticipan GCP as Backend (GCP)ORMERGEResultpaticpant CF soudFlter
  articpt FTasFindingsTable
UC e page (.., GDPRCRa  fomrouteFETCH: fetchAllludsReort(frmwkKy,)ar Pallel cloudfesFETHWSPOST/pi/get-repr{fraewokKeFETCHAZPOST/pi/g-tfraewokKeFETCHGP POST/pi/g-rtfraewokKeend

WSFETH: {sttu: "k", a:{...}}AZ-->>FETH: {sttu: "er", rro"Netwk rror}GCPFETH: {sttu"k", ata: {...}}
FETHORMsResultswsFETHORMesultsFETHERGEReults[ResultRsultResult]ERGE: [...sorted]:{...}F: Redwth coudSatuss
    CD->>T: Rnde with UF: Ck"AW" FD: nFlterChg("w")
    CD->>FT-rewth fiedf: a UsIDs IdusryCC  cmplinceConfigSB  SideBHltc  In sectoSBR wth iheltharCC: ReheltharCC-{: ["hipaa"], : ["nist", "is27001"], o:[...]}IDD: Ree frmewrk cs in 3 tiers
    U->>IDHPAASBpReespag at aggrgate.Rplcinge-c `mewokDhbor`pttrnmulti- paalllfethig  "so2"|"fdrmp"|"w" |"ci" |"is"acoDisDshbd   s, // from parent
  etSelectedMenu   nt — for navigation from Idusry cardspale via `fchAllCoudsRport dchm fReneader,ccoundropwn(AWS/Azur/GCP dysd),fl,ummrcard, chrs,fndg table,indig rawerHale p-cloudeottserr bannrs andrylogiShwemptysae whenovilaisfound Stickyfitrwth coud oggl buttosaper-seledFiter:tng)=>vis(gren=ok, e=errrgray=)onach cloud buttnper-cludsitoltipsDeful is always "all" — hardcoded `useState("all")`Redesningwth card inmandator/recommended/optionalsrom paret Read industrycnfigfromseconMANDATORYRECOMMENDED accentOPTIONAL accentframework ,andabutton
- Ccignvigateo th orrsponig  pgvi`sSeledMeu`hanctend the ex`FindingT`t suprCScompliance show"Clod"um(efult fle)show "Source" column ()
deaultSeveritySt,// boe— ort y severity Critical→Lw by defult (efault fale) s
-We`dfautSeveritySrt=tre`, aply daultotder:Crl → Hih → Mium→Lw
-B — existing framework pages unaffectedismodlfralldshboad viewsunique   suce     always— (`valu— eforceby normalzao— pecomputed duing normlizationin-empy trigUniedFi[]strig or n
};
```

**ValidationRules**:
-`status` must b one of `"ok"`, `"e"`,`"epty"`
- Whn `tatu === "error"`, `error` must be  non-mpty and `findings` must be `[]`- When `status === "empty"`, `findings` must be `[]` and `error` must be `null`- When `status === "ok"`, `findings` may be non-empty and `error must be nullt
const MergeResul = {  findings: [ UnifiedFinding[] — sorted Critical→Low /],
  cloudStatuses: {
    aws:   { status: "ok",    lastScanned: "...", error: null },  azre: { stas: "error", lasScanned: null,  error:"Netwrkrro" },
    cp:   { status: "empty", lastScanned: "...", rror: nll },
  },
};
```

**Vaidan Rles**:
- `fs` mutbesord byeverity: Critical → Hh → Mdium → Low
-`clouStuses`mut conain exaly 3 keys: `aws`, `az`, `gcp`- Each cloud statusmustform to `{ tats, lastScann, error }`shape

###e Framwork Config

```javcript
export cnst COMPLIANCE_FRAMEWORKS = {
  gdp:     { key: "gpr",     label: "GDPR",             ullName: "Geneal DataPotection Rgulation",          ico: "🔒", graint: "fom-blue-600 to-digo-600",    reportType: "dpr" },  pcidss:   { key:"pidss",   label: "PCI DSS",           fullName: "Payment Card Idutry DaaScurity Standad", icon: "💳", radint: "from-prpe-600 to-indigo-600",  reporType:"pcidss"},  hipaa:    { key: "hipaa",    label: "HIPAA",           ullName: "Health Insurance Portabilty a Accountability Act", co: "🏥", radient: "from-emerald-600 to-teal-600", reportType: "hipaa" },
  soc2:     { key: "oc2",     label"SOC2",             fullName: "Service Orgazation Control 2",              icon: "🛡️", gradient: "rom-volt-600 to-purple-600",  reportType: "soc2" },
  feramp:  { key: "fedramp",  label: "edRAMP",           fullName: "Federal Rsk a Authorzatio ManaementProgram", icon: "🏛️", gradient: "from-red-600 to-roe-600",     repTyp: "feramp"},
  waf:     { key: "wafr",     label: "AWS Well-Archeted", fullNme: "AWS Wel-Architected Framewrk Revie",  icon: "☁️" gradient: "from-orange-500 to-amber-600",   reportType: "wafr" },is:      { key: "cis",      abel: "CIS Benchmark",     fullName: "Center fr Internet Secrity Benchmark",      icon: "📋", graien: "from-cyn-600 o-bl-600",     reportType"cis" },nist:   { key: "nist",     lbel: "NIST CSF",          fullName: "NIST Cybersecurity Frameork",                icon: "🔬", gradient: "from-late-600 to-gray-700",    reportType"nist"},
 nist80053:key: "ni80053", lbel: "NIST 800-53",      fllName: "NIST Special Publication 800-53",             icon: "📜", gradient: "from-late-700 to-zinc-700",    reportTypenist80053" },
  is27001: { ey: iso27001"label:"ISO27001",        fulNme: "ISO/IEC 27001 Informaion eurity",          icon: "🌐", grdiet: "from-teal-600 to-cya-600",    rportTypeiso701" },
  iso718: { key: "iso7018", label: "ISO 708",         fullName: "ISO/IEC 2718 Cloud Privacy",                 icon: "☁️", gradient "from-sky-60 to-blue-6    rptType "iso27018" },
};
```

###IdstryConfig

```javascriptexport const INDUSTRY_CONFIG={
healthc
    key:"healhcare", label: "Helhcare", icon: "🏥",
    decriptionHIPAA-centric complianc fo healthcae ganizations
    mandatory:["hipa"],
    recommended: ["nist", "io27001"],
    opional: ["iso27018", "is"],
  },
  fince: {
    ky"finace", abe: "Finance", icon: "💳"
  dsciptinPCI DSS and SOC 2 focused complianc f financialsvices",
    mandaty: ["pcidss,"soc2"]reommended: ["nist", "iso27001"],
    otional ["cis"],
  },
saas:
    key: "saas", label: "SaaS", icon: "☁️",
   decripion: "SOC 2 and GDPR compliance for SaaS plform",
    mandatory ["soc2","gdpr],
    rcomended: ["iso27001", "nist"],
    otional: ["cis", "wafr"],
  },
  governmen: {
    ke: "governmentbel: "Government", icon: "🏛️",
    decripion: "FedRAMP and NIT omplince for governmet agecis",
    manatory ["fedramp",nist853"],
    recommended ["nist", "cis"],
    optional ["iso271],
  }
  ecommerce: {
    key:"ecommce", label: "E-commece", icn: "🛒",
    desciption "PCI DSS and GDPRcompliace for e-commerce patforms",
    mandatory: ["pcidss", "gdpr"],
    recommended: ["soc2", "iso27001"],
    optiona:["cis"]