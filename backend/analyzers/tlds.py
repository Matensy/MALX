"""Offline TLD list (no network lookups). Covers ccTLDs and widely used gTLDs."""

CCTLDS = set("""
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk
fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir
is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk
ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl
pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc
td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
""".split())

GTLDS = set("""
com net org edu gov mil int info biz name pro aero coop museum mobi asia tel travel jobs cat xxx post arpa
onion app dev xyz top site online club shop store tech space website live life world today news blog cloud
link click download zip mov icu cyou rest monster buzz work fun host press digital email agency company
solutions services network systems global group media studio design capital finance money bank bid win vip
loan men date stream trade racing review party science webcam faith accountant cricket kim country gdn lol
best uno page google amazon microsoft apple ovh one red blue pink black wiki land plus tools zone center
support software codes academy education school university college events social chat team games game
casino bet poker video tube photo pics art music radio tv sex porn adult dating love family guru ninja
rocks expert lat moscow tokyo berlin london paris nyc vegas africa asia us biz reviews market markets
exchange cash credit gold trading crypto security secure protection safe cyber limited ltd inc llc gmbh
cfd sbs bond quest beauty hair skin makeup luxury fashion boutique store mom kids baby run fit fitness
health care clinic hospital doctor dental pharmacy energy solar green eco garden farm city town
""".split())

ALL_TLDS = CCTLDS | GTLDS

# ccTLDs that collide with file extensions or common words/identifiers in code
# ("setup.py", "run.sh", "obj.id"): bare domains on them need stronger context.
EXTENSION_LIKE_TLDS = {"py", "sh", "so", "pl", "rs", "md", "cc", "ps", "ai", "pm", "sc", "js", "ts", "rb", "go",
                       "do", "in", "it", "is", "to", "me", "am", "as", "at", "be", "by", "id", "im", "no", "on",
                       "or", "tv", "ws", "cs", "mk", "ml", "mm", "ms", "ma", "mo", "np", "nu", "re", "st", "ac",
                       "ad", "al", "an", "ar", "bz", "cd", "cv", "dj", "fm", "gd", "hr", "hm", "jp", "la", "lb",
                       "ls", "lu", "mp", "mu", "pa", "pe", "pg", "ph", "pk", "pr", "py", "sa", "sb", "sd", "se",
                       "sg", "si", "sk", "sl", "sm", "sn", "sr", "sv", "tc", "td", "tf", "tg", "th", "tk", "tl",
                       "tm", "tn", "tr", "tt", "tw", "ua", "ug", "us", "uy", "va", "vc", "ve", "vg", "vi", "vn",
                       "vu", "wf", "ye", "yt", "za", "zm", "zw", "eg", "er", "es", "et", "gl", "gr", "gs", "gt",
                       "hu", "ie", "il", "io", "iq", "ir", "je", "jo", "ke", "kg", "kh", "ki", "km", "kn", "kp",
                       "kr", "kw", "ky", "kz", "li", "lk", "lr", "lt", "lv", "ly", "mc", "md", "mg", "mh", "mn",
                       "mq", "mr", "mt", "mv", "mw", "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl",
                       "nr", "nz", "om", "pf", "pn", "ps", "pt", "pw", "qa", "ro", "rw", "sc", "sh", "sx", "sy",
                       "sz", "tj", "to"}

# TLDs accepted for *bare* domains found in strings (outside URLs / e-mails).
# Long-tail word TLDs (".store", ".name", ".host", ".email"...) collide with code such as
# "this.store" or "user.email", so they are only accepted inside URLs.
BARE_TLDS = CCTLDS | {"com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "onion", "top", "xyz",
                      "club", "online", "site", "icu", "cyou", "su", "pw", "tk", "monster", "buzz", "rest", "bond",
                      "sbs", "cfd", "lat", "quest", "mobi", "asia", "zip", "mov"}
