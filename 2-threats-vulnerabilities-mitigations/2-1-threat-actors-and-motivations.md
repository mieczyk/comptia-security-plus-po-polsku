# 2.1 Compare and contrast common threat actors and motivations
*Porównaj ze sobą i wskaż różnice pomiędzy typowymi sprawcami zagrożeń oraz motywacjami, którymi się kierują.*

Zanim zaczniemy bronić organizacji, warto wiedzieć, **przed kim** się bronimy i **dlaczego** ktoś miałby nas w ogóle zaatakować. Ta sama luka w zabezpieczeniach będzie inaczej wykorzystana przez nastolatka, który właśnie pobrał gotowe narzędzie z internetu, a inaczej przez grupę finansowaną przez obce państwo, która ma czas, pieniądze i cierpliwość.

Na egzaminie pytania z tego zakresu mają zwykle formę krótkiego scenariusza: ktoś coś zrobił, w określony sposób i z określonym skutkiem, a my mamy wskazać, **kto** najprawdopodobniej stoi za atakiem albo **jaki** miał motyw. Dlatego oprócz definicji warto zapamiętać kluczowe cechy każdego sprawcy, które pozwolą go rozpoznać w opisie.

Kilka słów o terminologii. Angielski termin ***threat actor*** w polskich tekstach branżowych najczęściej pojawia się jako **aktor zagrożeń** (kalka, ale powszechnie stosowana), **sprawca zagrożenia** lub po prostu **napastnik/atakujący**. Polskie opracowanie słownika NIST (ang. *National Institute of Standards and Technology*, amerykański instytut normalizacyjny), czyli dokument [NSC 7298](https://www.gov.pl/attachment/48226cb6-29d4-49f9-860f-acd703072e60) z serii Narodowych Standardów Cyberbezpieczeństwa (NSC), używa określenia **czynnik zagrożenia** (ang. *threat agent*). W tym opracowaniu posługujemy się określeniem **sprawca** (zagrożeń), a *aktora zagrożeń* warto znać, bo często pojawia się w tekstach branżowych.
# Threat actors
**Sprawca (aktor) zagrożeń to osoba, grupa lub organizacja, która celowo (lub nieumyślnie) działa na szkodę systemów, danych albo ludzi**. Poniżej znajdują się kategorie sprawców wymienione w celach egzaminu SY0-701. Pamiętajmy, że w rzeczywistości granice między nimi bywają płynne: grupa przestępcza może pracować na zlecenie państwa, a haktywista może korzystać z narzędzi kupionych od przestępców.
## Nation-state
**Grupy sponsorowane przez państwo**, czyli **sprawcy działający na zlecenie państwa lub z jego cichym przyzwoleniem (ang. *nation-state*, *state-sponsored*), zazwyczaj powiązani ze służbami specjalnymi lub wojskiem**. To najgroźniejsza kategoria sprawców, ponieważ może dysponować ogromnymi zasobami, szczególnie w przypadku takich potęg wywiadowczych, jak Chiny, Rosja, USA czy Izrael: pieniędzmi, ludźmi, czasem, a niekiedy także wiedzą o lukach nieznanych jeszcze producentowi ani obrońcom (ang. *zero-day vulnerability*).

Z tą kategorią często wiąże się pojęcie **APT** (ang. *Advanced Persistent Threat*), czyli **zaawansowanego, trwałego zagrożenia**. Każde słowo w tej nazwie ma znaczenie:
- ***Advanced*** – atakujący stosują wyrafinowane techniki i narzędzia, często przygotowane specjalnie pod konkretny cel.
- ***Persistent*** – przede wszystkim **upór i konsekwencja w dążeniu do celu**: gdy jedna próba się nie powiedzie, atakujący nie rezygnuje, tylko szuka innej drogi, nawet przez wiele miesięcy. Celem nie jest szybki zysk, ale długotrwała, niezauważona obecność w zaatakowanej sieci. Taki *cichy lokator* potrafi przebywać w systemach ofiary miesiącami, a nawet latami, a wykryty i usunięty często próbuje wrócić.
- ***Threat*** – za atakiem stoi zorganizowana, zdeterminowana grupa ludzi, a nie przypadkowy program.

Techniki typowe dla APT nie są jednak zarezerwowane dla państw. Długotrwałe, starannie przygotowane ataki prowadzą też:
- **zorganizowane grupy przestępcze** nastawione na zysk (patrz [Organized crime](#organized-crime));
- **cybernajemnicy** (ang. *cyber mercenaries*, *hack-for-hire*), czyli firmy i grupy prowadzące **komercyjne cyberszpiegostwo** na zlecenie: włamują się do wskazanych osób lub organizacji albo sprzedają narzędzia szpiegujące. Przykładem jest izraelska firma NSO Group, twórca oprogramowania szpiegującego Pegasus, którą w 2021 r. USA wpisały na listę podmiotów objętych ograniczeniami eksportowymi ([komunikat Departamentu Handlu USA](https://www.commerce.gov/news/press-releases/2021/11/commerce-adds-nso-group-and-other-foreign-companies-entity-list));
- sprawcy **szpiegostwa przemysłowego** (patrz [Espionage](#espionage)), którzy wykradają tajemnice handlowe na rzecz konkurencji.

Klientem takich grup bywa państwo, ale nie musi. Dlatego mogą one, choć nie muszą, zazębiać się z kategorią *nation-state*.

Grupom APT nadaje się nazwy i numery, żeby można było śledzić ich działalność w czasie. Przykładowo, grupa **APT28** (znana też jako *Fancy Bear*) jest wiązana z rosyjskim wywiadem wojskowym, a w 2024 r. polski rząd publicznie przypisał rosyjskiemu wywiadowi wojskowemu kampanię wymierzoną w polskie instytucje państwowe ([Notes from Poland](https://notesfrompoland.com/2024/05/09/russian-hackers-target-polish-government-bodies/)). Z kolei grupa **Lazarus**, powiązana z Koreą Północną, słynie z kradzieży kryptowalut, z których dochody zasilają budżet tego państwa (w 2025 r. FBI przypisało północnokoreańskim hakerom kradzież kryptowalut o wartości ok. 1,5 mld USD z giełdy Bybit – [komunikat FBI](https://www.ic3.gov/PSA/2025/PSA250226)). Jak widać, cele państwowych grup nie zawsze są czysto szpiegowskie.

**Typowe cechy** (*key indicators*), które na egzaminie wskazują na *nation-state*:
- cel o znaczeniu strategicznym: administracja, wojsko, infrastruktura krytyczna (ang. *critical infrastructure*: energetyka, wodociągi, transport), przemysł zbrojeniowy;
- długi czas niezauważonej obecności w sieci ofiary;
- bardzo wysokie zaawansowanie techniczne, własne narzędzia, wykorzystanie luk *zero-day*;
- motywacja: szpiegostwo, wpływ polityczny, przygotowanie do konfliktu lub sam konflikt (wojna).
## Unskilled attacker
**Napastnik bez umiejętności**, czyli **osoba bez specjalistycznej wiedzy, która korzysta z gotowych narzędzi, skryptów i instrukcji przygotowanych przez innych**. W poprzedniej edycji egzaminu (SY0-601) ta kategoria nazywała się ***script kiddie***, i pod tą nazwą najczęściej spotkamy ją w branży. Określenie jest nieco pogardliwe: chodzi o kogoś, kto uruchamia cudze skrypty, nie do końca rozumiejąc, jak działają.

Nie oznacza to jednak, że takiego napastnika można lekceważyć. Dzisiaj za kilkadziesiąt złotych można *wynająć* atak DDoS (ang. *Distributed Denial of Service*, rozproszona odmowa usługi) w serwisie typu *booter/stresser* (ang. *DDoS-for-hire*) albo kupić gotowy zestaw do phishingu (ang. *phishing kit*). Bariera wejścia jest więc bardzo niska, a skutki potrafią być dotkliwe, szczególnie dla słabo zabezpieczonych organizacji.

**Cechy:** niski poziom zaawansowania, brak lub niewielkie zasoby finansowe, zazwyczaj działanie z zewnątrz. Motywacja bywa różna: ciekawość, chęć popisania się przed znajomymi, zemsta (np. na szkole), drobny zysk albo po prostu *zrobienie zamieszania*.
## Hacktivist
**Haktywista** (ang. *hacktivist*, połączenie słów *hacker* i *activist*) to **osoba lub grupa, która przeprowadza ataki, aby promować określone poglądy polityczne, społeczne lub ideologiczne**. Celem nie jest zysk finansowy, ale nagłośnienie sprawy, ośmieszenie przeciwnika lub utrudnienie mu działania.

Typowe działania haktywistów to:
- ataki DDoS, które czasowo wyłączają strony internetowe,
- podmiana zawartości strony (ang. *website defacement*), np. na hasło polityczne,
- wykradanie i publikowanie poufnych dokumentów (ang. *data leak*),
- ujawnianie prywatnych informacji o konkretnych osobach (ang. *doxing*).

Najbardziej znanym przykładem jest luźny ruch **Anonymous**. Z naszego podwórka dobrym przykładem jest prorosyjska grupa **NoName057(16)**, która od 2022 r. regularnie atakuje DDoS-em strony polskich instytucji, firm, samorządów, a nawet partii politycznych w czasie kampanii wyborczych, ogłaszając swoje *sukcesy* w mediach społecznościowych. W 2025 r. przeciwko jej infrastrukturze przeprowadzono międzynarodową operację z udziałem Europolu i polskiej policji ([gov.pl](https://www.gov.pl/web/po-plock/operacja-wymierzona-w-prorosyjska-siec-cyberprzestepcza-noname05716)).

Warto zauważyć, że **granica między haktywistą a sprawcą państwowym bywa bardzo cienka**: część grup przedstawiających się jako *niezależni aktywiści* w rzeczywistości działa w interesie konkretnego państwa.

**Cechy:** działanie z zewnątrz, zasoby zwykle ograniczone (choć niektóre grupy mają zaskakująco duże możliwości), poziom zaawansowania technicznego od niskiego do wysokiego. Motywacja: przekonania polityczne i filozoficzne (ang. *philosophical/political beliefs*).
## Insider threat
**Zagrożenie wewnętrzne** (ang. *insider threat*) to **zagrożenie wynikające z wykorzystania dostępu lub wiedzy zdobytej dzięki powiązaniu z organizacją**. Jego źródłem może być pracownik, kontraktor, partner biznesowy, a także były pracownik, który zachował dostęp do systemów lub wcześniej pozyskał poufne informacje. To kategoria szczególnie niebezpieczna, ponieważ taka osoba:
- **nie musi się nigdzie *włamywać***, bo ma już wstęp do budynku i posiada dane dostępowe do systemów,
- **zna organizację od środka**: wie, gdzie leżą cenne dane i w których miejscach zabezpieczenia są niewystarczające,
- **budzi mniej podejrzeń**, bo jej aktywność w systemach wygląda jak zwykła praca.

Pamiętajmy, że zagrożenie wewnętrzne **nie zawsze wynika ze złej woli**. Wyróżniamy:
- **sprawców celowych** (ang. *malicious insider*) – np. pracownik, który przed odejściem do konkurencji kopiuje bazę klientów, albo rozżalona osoba, która mści się na pracodawcy;
- **sprawców nieumyślnych** (ang. *unintentional/negligent insider*) – np. pracownik, który wyśle arkusz z danymi osobowymi do niewłaściwego odbiorcy albo da się nabrać na phishing.

Głośnym przykładem celowego działania z pobudek ideologicznych jest sprawa Edwarda Snowdena, który w 2013 r., jako pracownik firmy zewnętrznej z dostępem do systemów amerykańskiej NSA (ang. *National Security Agency*, Agencja Bezpieczeństwa Narodowego), wyniósł i ujawnił tajne dokumenty.

**Cechy:** działanie **od wewnątrz** (ang. *internal*), zasoby zwykle niewielkie, ale za to dostęp i wiedza bardzo duże; poziom zaawansowania technicznego bywa różny. Motywacje: zemsta, zysk finansowy, przekonania, szantaż, a w przypadku sprawców nieumyślnych – zwykła nieuwaga.
## Organized crime
**Zorganizowane grupy przestępcze** (ang. *organized crime*) działają w cyberprzestrzeni tak samo, jak w świecie fizycznym: **ich głównym celem są pieniądze**. Współczesna cyberprzestępczość przypomina zresztą regularną branżę usługową, z podziałem ról i *produktami* sprzedawanymi innym przestępcom:
- twórcy złośliwego oprogramowania udostępniają je w modelu abonamentowym (ang. *Malware-as-a-Service*, *MaaS*), a gangi ransomware – w modelu ***Ransomware-as-a-Service* (RaaS)**, w którym *partnerzy* (ang. *affiliates*) przeprowadzają ataki i dzielą się okupem z twórcami;
- **brokerzy pierwszego dostępu** (ang. *Initial Access Brokers*, *IAB*) włamują się do firm i sprzedają gotowy dostęp kolejnym grupom;
- osobne grupy zajmują się praniem pieniędzy, obsługą *infolinii* dla ofiar czy negocjacjami okupu.

Przykładem jest grupa **LockBit**, przez kilka lat jedna z najaktywniejszych grup ransomware na świecie, której infrastrukturę w 2024 r. przejęły służby kilku państw w ramach międzynarodowej operacji *Cronos*.

**Cechy:** działanie z zewnątrz, duże zasoby finansowe (zarabiają, więc inwestują), wysoki poziom zaawansowania. Motywacja: przede wszystkim zysk finansowy, osiągany przez szantaż (okup za odszyfrowanie lub za niepublikowanie danych), kradzież danych i kryptowalut czy oszustwa.
## Shadow IT
***Shadow IT*** (dosłownie: *IT w cieniu*) to **systemy, aplikacje, usługi chmurowe i urządzenia używane w organizacji bez wiedzy i zgody działu IT**. Na pierwszy rzut oka może dziwić, że ta pozycja znalazła się na liście sprawców zagrożeń, skoro nikt tu nikogo celowo nie atakuje. Chodzi jednak o to, że **zagrożenie stwarzają sami pracownicy**, którzy w dobrej wierze, *żeby było szybciej*, omijają oficjalne procedury.

Przykłady:
- zespół trzyma firmowe dokumenty na prywatnym koncie w chmurze, bo *tak wygodniej je udostępniać*;
- pracownik wkleja fragmenty umowy z klientem do publicznego czatbota AI, żeby szybciej przygotować streszczenie (ten przypadek bywa nazywany ***shadow AI***);
- ktoś podłącza do sieci firmowej własny router Wi-Fi, bo zasięg w sali konferencyjnej był za słaby.

Problem polega na tym, że **nie da się chronić czegoś, o czego istnieniu się nie wie**. Takie zasoby nie są objęte aktualizacjami, kopiami zapasowymi, monitoringiem ani politykami bezpieczeństwa, a dane w nich przechowywane wymykają się spod kontroli organizacji.

**Cechy:** źródło wewnętrzne, brak złych intencji, niewielkie zasoby i niski poziom zaawansowania. Motywacją jest najczęściej wygoda i chęć szybszego wykonania pracy.
# Attributes of actors
**Atrybuty sprawców.** Poszczególnych sprawców można porównywać według trzech cech (atrybutów) wymienionych w celach egzaminu: **pochodzenia** (wewnętrzni czy zewnętrzni), **zasobów i finansowania** oraz **poziomu zaawansowania**. Omawiamy je poniżej, a na końcu zestawiamy w tabeli. Na egzaminie to właśnie one najczęściej pomagają rozpoznać, z kim mamy do czynienia w opisanym scenariuszu.
## Internal/external
**Sprawcy wewnętrzni i zewnętrzni**, czyli **podział ze względu na to, skąd pochodzi zagrożenie**:
- **Wewnętrzne** (ang. *internal*) – sprawca ma uprawniony dostęp do organizacji: pracownik, kontraktor, partner, a także *shadow IT*.
- **Zewnętrzne** (ang. *external*) – sprawca działa spoza organizacji: przestępcy, haktywiści, grupy państwowe, *unskilled attackers* (w SY0-601: *script kiddies*), czyli atakujący bez umiejętności, kupujący gotowe rozwiązania i korzystający ze złośliwych skryptów według dostarczonej instrukcji.

Warto pamiętać, że sprawca zewnętrzny może próbować wykorzystać dostęp przysługujący osobom wewnątrz organizacji, np. poprzez kradzież danych logowania, przekupienie pracownika lub nakłonienie go do współpracy. Samo przejęcie konta pracownika nie oznacza jednak, że napastnik staje się sprawcą wewnętrznym (ang. *insider threat*).
## Resources/funding
**Zasoby i finansowanie**, czyli to, czym sprawca dysponuje: pieniądze, ludzie, sprzęt, infrastruktura, a także **czas**. Przykładowo, grupa sponsorowana przez państwo może przez miesiące przygotowywać atak na jeden cel. Natomiast napastnik bez odpowiednio dużych środków najprawdopodobniej zrezygnuje już po kilku godzinach nieudanych prób.

Im większe zasoby, tym bardziej wyrafinowanego i długotrwałego ataku można się spodziewać, i tym trudniej się przed nim obronić.
## Level of sophistication/capability
**Poziom zaawansowania i możliwości technicznych**: od uruchamiania gotowych narzędzi (*unskilled attacker*), przez sprawne posługiwanie się znanymi technikami, aż po tworzenie własnego złośliwego oprogramowania i wykorzystywanie nieznanych wcześniej luk (*zero-day*) przez grupy APT.

Zasoby i zaawansowanie zwykle idą w parze, choć nie zawsze: *insider* może mieć niewielkie umiejętności techniczne, a mimo to wyrządzić ogromne szkody, bo ma dostęp i wiedzę o potencjalnym celu.
### Podsumowanie
Poniższa tabela zestawia typowe cechy poszczególnych sprawców. To uogólnienie, które pomaga na egzaminie; w rzeczywistości od każdej reguły zdarzają się wyjątki.

| Sprawca | Pochodzenie | Zasoby/finansowanie | Zaawansowanie | Typowe motywacje |
|---|---|---|---|---|
| *Nation-state* | zewnętrzne | bardzo duże | bardzo wysokie | szpiegostwo, polityka, wojna, zakłócenie działania |
| *Unskilled attacker* | zewnętrzne | niewielkie | niskie | ciekawość, popis, chaos, zemsta |
| *Hacktivist* | zewnętrzne | ograniczone | od niskiego do wysokiego | przekonania polityczne i filozoficzne |
| *Insider threat* | wewnętrzne | niewielkie (ale duży dostęp) | różne | zemsta, zysk, przekonania; albo nieuwaga |
| *Organized crime* | zewnętrzne | duże | wysokie | zysk finansowy, szantaż |
| *Shadow IT* | wewnętrzne | niewielkie | niskie | wygoda (brak złych intencji) |
# Motivations
**Motywacja odpowiada na pytanie: dlaczego?** Znając motyw, łatwiej przewidzieć, co sprawca zrobi, kiedy już dostanie się do środka: czy zacznie szyfrować dane, czy po cichu je wynosić, czy może po prostu wszystko zniszczy. Jeden sprawca może mieć kilka motywacji naraz.
## Data exfiltration
**Eksfiltracja danych**, czyli **nieuprawnione wyprowadzenie danych z organizacji** (dosłownie: *wykradanie*). Dane są cenne same w sobie: dane osobowe (ang. *PII – Personally Identifiable Information*) i dane kart płatniczych można sprzedać, tajemnice handlowe przekazać konkurencji, a dane logowania wykorzystać w kolejnych atakach. Wykradzione dane służą też do szantażu (patrz niżej). Eksfiltracja jest celem zarówno przestępców, jak i grup państwowych czy nieuczciwych pracowników.
## Espionage
**Szpiegostwo** (ang. *espionage*) to **pozyskiwanie tajnych informacji**: państwowych, wojskowych, politycznych albo przemysłowych. Szpiegostwo państwowe to domena grup *nation-state*; szpiegostwo przemysłowe (ang. *corporate/industrial espionage*) może prowadzić także konkurencja, często przy pomocy nieuczciwego pracownika (*insider*). Cechą charakterystyczną jest **dyskrecja**: szpieg nie chce zostać zauważony, więc niczego nie niszczy i nie żąda okupu.
## Service disruption
**Zakłócenie działania usług** (ang. *service disruption*), czyli **uniemożliwienie organizacji normalnego funkcjonowania**: wyłączenie strony internetowej, systemu sprzedaży, poczty czy linii produkcyjnej. Typowym narzędziem są ataki DDoS. Przerwa w działaniu oznacza straty finansowe i wizerunkowe, a w przypadku infrastruktury krytycznej (energetyka, szpitale) może zagrażać życiu ludzi.
## Blackmail
**Szantaż** (ang. *blackmail*) polega na **wymuszeniu korzyści groźbą**: 
- *Zapłać, bo opublikujemy wasze dane.*
- *Zapłać, bo nie odzyskacie plików.*
- *Zapłać, to przestaniemy blokować waszą stronę.*

Szantaż to fundament modelu biznesowego gangów ransomware, które często stosują tzw. **podwójne wymuszenie** (ang. *double extortion*): najpierw wykradają dane, potem je szyfrują i żądają zapłaty zarówno za klucz, jak i za milczenie. Szantażowany może być też pojedynczy pracownik, którego sprawca zmusza w ten sposób do współpracy.
## Financial gain
**Zysk finansowy** (ang. *financial gain*) to **najczęstsza motywacja cyberprzestępców**. Pieniądze przy atakach hakerskich można zdobyć na wiele sposobów, na przykład poprzez: okup, kradzież środków z kont bankowych, kradzież kryptowalut, oszustwa typu *na prezesa* (ang. *Business Email Compromise*, BEC), sprzedaż wykradzionych danych albo wynajem zainfekowanych komputerów (botnetów). Jeśli w scenariuszu na egzaminie pojawia się żądanie zapłaty lub kradzież pieniędzy, najprawdopodobniej chodzi o *organized crime* i tę właśnie motywację.
## Philosophical/political beliefs
**Przekonania filozoficzne i polityczne** to główny napęd **haktywistów**. Atak ma przede wszystkim przekazać komunikat: nagłośnić sprawę, ośmieszyć przeciwnika, ukarać firmę za jej działalność. Z tego powodu takie ataki są zwykle **głośne i widoczne** (podmieniona strona, DDoS w dniu ważnego wydarzenia), a sprawcy chętnie się do nich przyznają.
## Ethical
**Motywacja etyczna** (ang. *ethical*) dotyczy osób, które **szukają podatności po to, by je naprawić, a nie wykorzystać**. W branży mówi się o hakerach w *białych kapeluszach* (ang. *white hat*), w odróżnieniu od przestępców w *czarnych kapeluszach* (ang. *black hat*) oraz osób działających na granicy prawa, czyli w *szarych kapeluszach* (ang. *grey hat*).

Ważne rozróżnienie: test penetracyjny (ang. *penetration test*) czy program *bug bounty* odbywa się **za zgodą i według zasad** ustalonych z właścicielem systemu. Szukanie luk w cudzym systemie bez zgody, nawet w dobrej wierze, wciąż może zostać uznane za przestępstwo. Dlatego etyczny haker zgłasza znalezioną podatność zgodnie z zasadami **odpowiedzialnego ujawniania** (ang. *responsible/coordinated disclosure*; CERT Polska mówi o **skoordynowanym ujawnianiu podatności**), a w Polsce może w tym celu skorzystać na przykład z pośrednictwa CERT Polska (CERT, ang. *Computer Emergency Response Team*, zespół reagowania na incydenty komputerowe).
## Revenge
**Zemsta** (ang. *revenge*) to motywacja typowa dla **rozżalonych pracowników i byłych pracowników**, np. zwolnionych dyscyplinarnie albo pominiętych przy awansie. Mszczący się *insider* może skasować dane, sabotować system, którym się opiekował, albo wynieść poufne informacje i przekazać je konkurencji lub mediom. Dlatego tak ważna jest procedura odejścia pracownika z firmy (ang. *offboarding*), w tym natychmiastowe odebranie wszystkich uprawnień.
## Disruption/chaos
**Zamieszanie i chaos** (ang. *disruption/chaos*) to sytuacja, w której **sprawcy nie chodzi o pieniądze ani o konkretną sprawę, ale o samo wyrządzenie szkody i wywołanie zamętu**, czasem po prostu *dla zabawy* albo dla rozgłosu. Taka motywacja jest typowa dla mniej doświadczonych napastników (*unskilled attacker*), ale chaos jako cel może też wpisywać się w działania państwowe, kiedy chodzi o osłabienie zaufania obywateli do określonych instytucji.
## War
**Wojna** (ang. *war*) to motywacja **grup państwowych działających w ramach konfliktu zbrojnego albo przygotowujących się do niego**. Celem jest osłabienie przeciwnika: wyłączenie jego infrastruktury krytycznej, zniszczenie danych, sparaliżowanie łączności czy wojska. Cyberataki są dziś stałym elementem konfliktów i tzw. **działań hybrydowych** (ang. *hybrid warfare*), w których ataki w sieci łączą się z dezinformacją i sabotażem w świecie fizycznym.

Przykładem jest atak **NotPetya** z 2017 r. Złośliwe oprogramowanie, rozprowadzone przez zainfekowaną aktualizację popularnego na Ukrainie programu księgowego, udawało ransomware, ale w rzeczywistości bezpowrotnie niszczyło dane. Rządy USA i Wielkiej Brytanii przypisały ten atak rosyjskiemu wojsku. Choć celem była Ukraina, szkodnik rozprzestrzenił się na cały świat i sparaliżował m.in. globalne firmy logistyczne, a straty liczono w miliardach dolarów.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [NSC 7298 – Słownik pojęć z zakresu cyberbezpieczeństwa (polskie opracowanie NISTIR 7298), Ministerstwo Cyfryzacji](https://www.gov.pl/attachment/48226cb6-29d4-49f9-860f-acd703072e60)
- [CISA: Defining Insider Threats](https://www.cisa.gov/defining-insider-threats)
- [NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments](https://csrc.nist.gov/pubs/sp/800/30/r1/final)
- [Sekurak: artykuły z tagiem APT](https://sekurak.pl/tag/apt/)
- [U.S. Department of Commerce: Commerce Adds NSO Group and Other Foreign Companies to Entity List (2021)](https://www.commerce.gov/news/press-releases/2021/11/commerce-adds-nso-group-and-other-foreign-companies-entity-list)
