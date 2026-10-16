# 2.2 Explain common threat vectors and attack surfaces
Na egzaminie należy wykazać się znajomością i zrozumieniem przedstawionych poniżej zagrożeń i wektorów ataku.

Zanim przejdziemy do poszczególnych pozycji, wyjaśnijmy dwa pojęcia z tytułu tego zagadnienia:
- **Wektor ataku** (ang. *threat vector*, *attack vector*) to **droga, którą atakujący dostaje się do systemu albo dociera do ofiary**: wiadomość e-mail, zainfekowany pendrive, niezałatana usługa wystawiona do internetu.
- **Powierzchnia ataku** (ang. *attack surface*) to **suma wszystkich miejsc, przez które organizację można zaatakować**: każdy otwarty port, każda aplikacja, każde urządzenie i każdy pracownik z dostępem do poczty. Im większa powierzchnia ataku, tym więcej potencjalnych wektorów i tym trudniej wszystkiego dopilnować. Dlatego jedną z podstawowych zasad bezpieczeństwa jest **ograniczanie powierzchni ataku** (ang. *attack surface reduction*): wyłączamy to, czego nie używamy, i pilnujemy tego, co musi działać.

CERT Polska (CERT, ang. *Computer Emergency Response Team*, zespół reagowania na incydenty komputerowe) opisuje to zagadnienie z perspektywy organizacji w artykule [Zewnętrzna powierzchnia ataku](https://wiedza.cert.pl/odpornosc-infrastruktury/zewnetrzna-powierzchnia-ataku/zewnetrzna-powierzchnia-ataku/).
# Message-based
**Wektory oparte na wiadomościach**, czyli wszystkie kanały, przez które atakujący może wysłać ofierze treść: link, załącznik albo po prostu przekonującą historyjkę. To zdecydowanie najczęściej wykorzystywana grupa wektorów, bo dotarcie do człowieka jest tanie, a człowiek bywa najsłabszym ogniwem (więcej o tym w części [Human vectors/social engineering](#human-vectorssocial-engineering)).
## Email
**Poczta elektroniczna to od lat wektor numer jeden.** Za pomocą e-maila atakujący może:
- podesłać link do fałszywej strony logowania (phishing),
- dołączyć złośliwy załącznik (patrz [File-based](#file-based)),
- podszyć się pod przełożonego albo kontrahenta i poprosić o pilny przelew (ang. *Business Email Compromise*, BEC).

Problem w tym, że **protokół SMTP (ang. *Simple Mail Transfer Protocol*), na którym opiera się poczta, nie był projektowany z myślą o bezpieczeństwie** i sam z siebie nie weryfikuje, kto naprawdę jest nadawcą. Dlatego powstały dodatkowe mechanizmy, takie jak SPF (ang. *Sender Policy Framework*), DKIM (ang. *DomainKeys Identified Mail*) i DMARC (ang. *Domain-based Message Authentication, Reporting and Conformance*), które pozwalają serwerom pocztowym sprawdzić, czy wiadomość rzeczywiście pochodzi z domeny, którą podaje. Do tego dochodzą filtry antyspamowe i skanowanie załączników. Żaden z tych mechanizmów nie jest jednak doskonały, więc czujność odbiorcy wciąż pozostaje ostatnią linią obrony.
## Short Message Service (SMS)
**SMS** (ang. *Short Message Service*) to kanał wykorzystywany w atakach typu **smishing** (opisanych w części [Smishing](#smishing)). Wiadomości SMS mają kilka cech, które sprzyjają oszustom:
- są krótkie, więc łatwo ukryć w nich brak szczegółów, a skrócony link nie budzi podejrzeń;
- czytamy je zwykle na telefonie, w biegu, gdzie trudniej sprawdzić adres strony;
- numer nadawcy, a nawet jego nazwę (np. *InPost*, *Poczta*), można sfałszować (ang. *spoofing*).

W Polsce klasyką są SMS-y o *niedopłacie za przesyłkę*, *zaległej fakturze za prąd* czy *zablokowanym koncie*, z linkiem do fałszywej bramki płatności.
## Instant messaging (IM)
**Komunikatory internetowe** (ang. *instant messaging*), takie jak WhatsApp, Messenger, Signal, Telegram, ale także firmowe Microsoft Teams czy Slack. Atakujący wykorzystują je podobnie jak SMS-y i e-maile, z jedną ważną różnicą: **wiadomość często przychodzi od kogoś, kogo znamy**. Wystarczy, że przestępca przejmie konto (ang. *account takeover*) jednej osoby, a potem pisze do wszystkich jej znajomych. W Polsce doskonale znane jest oszustwo *na BLIKa*: znajomy na Messengerze pisze, że *pilnie potrzebuje kodu BLIK, bo zapomniał karty*, a w rzeczywistości po drugiej stronie siedzi oszust.

W firmach rośnie znaczenie ataków przez komunikatory służbowe: atakujący pisze na Teams, podając się za dział IT, i prosi o zainstalowanie *narzędzia do zdalnej pomocy* (ang. *remote access tool*). Wiadomość w firmowym komunikatorze budzi mniej podejrzeń niż e-mail, a filtry bezpieczeństwa są tu zwykle słabsze.
# Image-based
**Wektory oparte na obrazach.** Na pierwszy rzut oka obrazek wydaje się niegroźny, bo to *tylko* zdjęcie. Mimo to obrazy mogą posłużyć do ataku na kilka sposobów:
- **Złośliwy kod** (ang. *malicious code*) **w pliku graficznym.** Program wyświetlający obrazy musi przetworzyć (sparsować, ang. *parse*) plik, a w kodzie przetwarzającym mogą się zdarzyć błędy. Odpowiednio spreparowany plik potrafi taki błąd wykorzystać i uruchomić kod atakującego, czasem nawet bez żadnej akcji ofiary (tzw. atak ***zero-click***).
- **Format SVG.** Pliki SVG (ang. *Scalable Vector Graphics*, grafika wektorowa) są w rzeczywistości plikami tekstowymi w formacie XML (ang. *Extensible Markup Language*) i mogą zawierać skrypty JavaScript. Przestępcy wysyłają je jako *obrazek* w załączniku, a po otwarciu w przeglądarce skrypt przekierowuje ofiarę na stronę phishingową.
- **Kody QR.** Kod QR to obraz, który człowiek nie jest w stanie *przeczytać* bez telefonu. Atak polegający na podsunięciu fałszywego kodu QR nazywamy ***quishing*** (od *QR* + *phishing*). Przykład z naszego podwórka: [fałszywe kody QR naklejone na parkomatach w Krakowie](https://cyberdefence24.pl/cyberbezpieczenstwo/scam-w-krakowie-uwaga-na-falszywe-kody-qr-na-parkomatach), prowadzące do podrobionej strony płatności.
- **Steganografia** (ang. *steganography*). Dane lub kod mogą zostać ukryte wewnątrz zwyczajnie wyglądającego obrazu, np. żeby przemycić je przez filtry albo przekazać instrukcje złośliwemu oprogramowaniu (więcej w zagadnieniu 1.4, w części [Steganography](../1-general-security-concepts/1-4-cryptographic-solutions.md#steganography)).
# File-based
**Wektory oparte na plikach**, czyli wszelkiego rodzaju **złośliwe pliki**, które ofiara pobiera lub otwiera: załączniki do e-maili, pliki pobrane ze stron, pliki przesłane przez komunikator. Popularne formy:
- **Dokumenty pakietu Office z makrami.** Makro to mały program zapisany w dokumencie, np. w arkuszu Excel. Przez lata był to jeden z ulubionych sposobów na infekcję (*włącz edycję i makra, żeby zobaczyć treść faktury*). Microsoft od 2022 r. domyślnie blokuje makra w plikach pobranych z internetu, więc przestępcy coraz częściej sięgają po inne formaty.
- **Archiwa i obrazy dysków** (ZIP, RAR, 7z, ISO, IMG) – zawartość spakowanego pliku jest gorzej widoczna dla filtrów, a archiwum zabezpieczone hasłem bywa dla nich zupełnie nieprzejrzyste.
- **Pliki wykonywalne** (ang. *executables*) **i skrypty udające dokumenty**, np. *faktura.pdf.exe* (system może ukrywać rozszerzenia znanych typów plików), skróty (pliki .lnk) czy pliki JavaScript i VBS (ang. *Visual Basic Script*).
- **Pliki PDF** z odnośnikami do stron phishingowych lub wykorzystujące błędy w czytnikach PDF.

CERT Polska przygotował [przegląd fałszywych załączników](https://cert.pl/falszywe-zalaczniki), z którymi najczęściej spotykamy się w polskich kampaniach.
# Voice call
**Połączenia głosowe**, zarówno klasyczne telefoniczne, jak i VoIP (ang. *Voice over Internet Protocol*, telefonia internetowa). Atak przez telefon nazywamy ***vishingiem*** (opisanym w części [Vishing](#vishing)). Ten wektor jest skuteczny z kilku powodów:
- rozmowa na żywo wywiera presję czasu (ang. *urgency*): nie ma chwili, żeby się zastanowić albo kogoś zapytać;
- numer dzwoniącego można sfałszować (ang. *caller ID spoofing*), więc na ekranie może się wyświetlić prawdziwy numer banku;
- coraz łatwiej podrobić głos konkretnej osoby za pomocą sztucznej inteligencji (ang. *voice cloning*, *deepfake*), np. głos prezesa, który *pilnie potrzebuje przelewu*.

Typowe polskie scenariusze to telefon od *pracownika działu bezpieczeństwa banku* albo od *policjanta prowadzącego sprawę*, który przekonuje, że nasze pieniądze są zagrożone i trzeba je pilnie przelać na *bezpieczne konto*.
# Removable device
**Urządzenia wymienne**, czyli pendrive’y, zewnętrzne dyski, karty pamięci, a nawet kable i ładowarki. Ten wektor pozwala ominąć zabezpieczenia sieciowe, bo złośliwy kod trafia bezpośrednio do komputera, z pominięciem zapory sieciowej (ang. *firewall*) czy filtra poczty. Dotyczy to także sieci fizycznie odciętych od internetu (ang. *air-gapped*). Słynny robak (ang. *worm*) **Stuxnet**, który około 2010 r. uszkodził wirówki w irańskim zakładzie wzbogacania uranu, dostał się do odizolowanej sieci zakładu najprawdopodobniej właśnie na nośniku USB.

Popularne techniki:
- **Atak podrzuconym nośnikiem** (ang. *USB drop attack*, *baiting*, dosł. „zarzucanie przynęty”) – atakujący zostawia zainfekowane nośniki, najczęściej pendrive'y, na parkingu albo w recepcji firmy i liczy na ludzką ciekawość. Badania pokazują, że to działa zaskakująco dobrze: znalazca chce sprawdzić, do kogo należy zguba, więc podłącza nośnik do komputera.
- **Urządzenia udające klawiaturę** (ang. *HID – Human Interface Device*; np. *USB Rubber Ducky*, ataki typu *BadUSB*) – wyglądają jak zwykły pendrive, ale system rozpoznaje je jako klawiaturę. W kilka sekund po podłączeniu *wpisują* przygotowane polecenia szybciej niż człowiek.
- **Złośliwe kable i ładowarki** – kabel z ukrytym układem elektronicznym albo publiczna stacja ładowania, która zamiast samego prądu przesyła dane (ang. *juice jacking*).

Obrona: blokowanie lub kontrola portów USB, wyłączenie automatycznego uruchamiania, skanowanie nośników i, przede wszystkim, zasada: **nie podłączamy nośników nieznanego pochodzenia**.
# Vulnerable software
**Podatne oprogramowanie**, czyli aplikacje i systemy zawierające luki (podatności, ang. *vulnerabilities*), które atakujący może wykorzystać. Każdy program to potencjalny element powierzchni ataku, a im więcej oprogramowania, tym więcej rzeczy do aktualizowania. Dlatego tak ważne jest zarządzanie poprawkami (ang. *patch management*) i bieżąca inwentaryzacja (ang. *software inventory*) tego, co faktycznie mamy zainstalowane.
## Client-based vs. agentless
**Oprogramowanie instalowane na urządzeniu a bezagentowe.** W kontekście podatnego oprogramowania egzamin wymienia dwa modele działania aplikacji:
- **Oprogramowanie instalowane na urządzeniu** (ang. *client-based*), np. klient poczty, komunikator czy agent systemu bezpieczeństwa. Taka aplikacja jest obecna na każdym komputerze, na którym działa, więc **każda jej podatność dotyczy wszystkich tych urządzeń**. Trzeba też pilnować aktualizacji na każdym z nich, co w dużej organizacji bywa trudne.
- **Oprogramowanie bezagentowe** (ang. *agentless*), które nie wymaga instalowania niczego na stałe po stronie urządzenia: działa np. w przeglądarce albo jest uruchamiane zdalnie, tylko na czas wykonania zadania. Na urządzeniu jest mniej do aktualizowania, ale **podatności przenoszą się na stronę serwera** i usługi, z którą się łączymy. Luka po stronie serwera dotyczy od razu wszystkich użytkowników.

Żaden z modeli nie jest z definicji bezpieczniejszy. Chodzi o to, żeby rozumieć, **gdzie w danym modelu leży powierzchnia ataku** i gdzie trzeba wdrażać poprawki.
# Unsupported systems and applications
**Systemy i aplikacje bez wsparcia producenta**, czyli takie, dla których skończył się okres wsparcia (ang. *End of Life*, EOL). Producent nie publikuje już dla nich poprawek bezpieczeństwa, więc **każda nowo odkryta luka pozostaje otwarta na zawsze**. Przykładowo, wsparcie dla systemu Windows 10 zakończyło się w październiku 2025 r., a organizacje, które nadal z niego korzystają bez dodatkowego, płatnego wsparcia, nie otrzymują już łatek.

Doskonałą ilustracją problemu był atak ransomware **WannaCry** z 2017 r., który rozprzestrzeniał się błyskawicznie m.in. przez niezałatane i przestarzałe komputery z systemem Windows. Skala była tak duża, że Microsoft wyjątkowo wydał poprawkę nawet dla dawno niewspieranego systemu Windows XP.

Dlaczego organizacje w ogóle używają przestarzałych systemów? Często z konieczności: specjalistyczne oprogramowanie (np. sterujące maszynami w fabryce czy aparaturą medyczną) działa tylko na starym systemie, a wymiana jest bardzo kosztowna. W takiej sytuacji stosuje się **środki kompensujące** (ang. *compensating controls*, patrz zagadnienie 1.1, [Compensating](../1-general-security-concepts/1-1-security-controls.md#compensating)), np. odizolowanie takiego systemu w osobnym segmencie sieci (ang. *network segmentation*).
# Unsecure networks
**Niezabezpieczone sieci**, czyli sieci, w których atakujący może podsłuchiwać ruch (ang. *eavesdropping*, *sniffing*), podszywać się pod inne urządzenia albo po prostu się do nich podłączyć.
## Wireless
**Sieci bezprzewodowe** są szczególnie narażone, bo **sygnał radiowy nie kończy się na ścianach budynku**. Typowe problemy:
- **sieci otwarte**, bez szyfrowania (np. darmowe Wi-Fi w kawiarni), w których ruch innych użytkowników może zostać podsłuchany;
- **przestarzałe lub słabe zabezpieczenia**, np. protokół WEP (ang. *Wired Equivalent Privacy*, złamany wiele lat temu) albo WPA2 (ang. *Wi-Fi Protected Access 2*) z łatwym do odgadnięcia hasłem;
- **fałszywe punkty dostępowe** – atakujący stawia sieć o takiej samej nazwie jak prawdziwa (ang. *evil twin*), a urządzenia ofiar łączą się z nią, przekazując cały ruch przez sprzęt atakującego;
- **nieautoryzowane punkty dostępowe** (ang. *rogue access point*) podłączone do firmowej sieci, np. przez pracownika, który *chciał mieć lepszy zasięg* (patrz [Shadow IT](2-1-threat-actors-and-motivations.md#shadow-it)).
## Wired
**Sieci przewodowe** wydają się bezpieczniejsze, bo trzeba się do nich fizycznie podłączyć. Ale w wielu firmach wystarczy wejść do sali konferencyjnej i wpiąć laptopa do **aktywnego gniazdka sieciowego w ścianie**, żeby znaleźć się w sieci wewnętrznej. Jeśli sieć nie weryfikuje, jakie urządzenie się do niej podłącza, intruz ma otwartą drogę.

Obrona: kontrola dostępu do sieci (ang. *Network Access Control*, NAC) i uwierzytelnianie urządzeń w standardzie 802.1X (ang. *port-based authentication*), wyłączanie nieużywanych portów w przełącznikach oraz podział sieci na segmenty.
## Bluetooth
**Bluetooth** to technologia łączności bezprzewodowej krótkiego zasięgu, którą mamy w telefonach, laptopach, słuchawkach, samochodach czy urządzeniach medycznych. Zagrożenia związane z Bluetooth to m.in.:
- **bluejacking** – wysyłanie niechcianych wiadomości do urządzeń w pobliżu (raczej uciążliwe niż groźne);
- **bluesnarfing** – nieuprawniony dostęp do danych na urządzeniu, np. kontaktów czy wiadomości;
- **błędy w samej implementacji protokołu** – przykładem jest zestaw podatności **BlueBorne** (2017), które pozwalały przejąć kontrolę nad urządzeniem z włączonym Bluetooth bez parowania i bez wiedzy użytkownika.

Dobra praktyka: wyłączać Bluetooth, kiedy go nie używamy, nie ustawiać urządzenia w trybie wykrywalnym i nie akceptować próśb o parowanie od nieznanych urządzeń.
# Open service ports
**Otwarte porty usług.** Każda usługa sieciowa (serwer WWW, pulpit zdalny, udostępnianie plików, baza danych) *nasłuchuje* na określonym porcie. **Każdy otwarty port to potencjalne wejście do systemu**, a jeśli działająca na nim usługa ma podatność albo słabe hasło, atakujący może z niej skorzystać. Otwarte porty łatwo znaleźć: wystarczy skaner portów (ang. *port scanner*), np. Nmap, a wyszukiwarki takie jak Shodan stale indeksują urządzenia widoczne w internecie.

Szczególnie niebezpieczne jest wystawianie do internetu usług, które powinny być dostępne wyłącznie w sieci wewnętrznej. Przykłady:
- **RDP** (ang. *Remote Desktop Protocol*, pulpit zdalny, port 3389/TCP, gdzie TCP to ang. *Transmission Control Protocol*) – ulubiony cel ataków siłowych na hasła (ang. *brute force*) i częsty punkt wejścia gangów ransomware; krytyczna luka [BlueKeep (CVE-2019-0708)](https://www.cve.org/CVERecord?id=CVE-2019-0708) (CVE, ang. *Common Vulnerabilities and Exposures*, to publiczny rejestr podatności) pozwalała przejąć serwer RDP bez logowania;
- **SMB** (ang. *Server Message Block*, udostępnianie plików w Windows, port 445/TCP) – przez tę usługę rozprzestrzeniał się wspomniany wcześniej WannaCry;
- **Telnet** (port 23/TCP) – stary protokół zdalnego dostępu, który przesyła hasła otwartym tekstem (ang. *cleartext*).

Zasada jest prosta: **otwieramy tylko te porty, które są naprawdę potrzebne**, a resztę zamykamy na zaporze sieciowej i wyłączamy nieużywane usługi.
# Default credentials
**Domyślne dane logowania**, czyli fabryczne loginy i hasła ustawione przez producenta (np. *admin/admin*), których nikt nie zmienił po instalacji. Listy domyślnych haseł do tysięcy modeli routerów, kamer czy drukarek są ogólnodostępne w internecie, więc **atakujący nie musi niczego łamać, wystarczy, że się zaloguje**.

Najbardziej znanym przykładem jest botnet **Mirai** z 2016 r. Złośliwe oprogramowanie skanowało internet w poszukiwaniu urządzeń IoT (ang. *Internet of Things*, internet rzeczy; głównie kamer i rejestratorów wideo) i logowało się do nich przy użyciu kilkudziesięciu par domyślnych loginów i haseł. Z setek tysięcy przejętych urządzeń zbudowano botnet, który przeprowadził jedne z największych ataków DDoS (ang. *Distributed Denial of Service*, rozproszona odmowa usługi) w historii, czasowo utrudniając dostęp do wielu popularnych serwisów internetowych.

Obrona: zmiana domyślnych haseł natychmiast po instalacji (najlepiej jako stały punkt procedury wdrożenia każdego urządzenia), wyłączanie kont domyślnych i regularne przeglądy konfiguracji.
# Supply chain
**Łańcuch dostaw** (ang. *supply chain*) to wszyscy zewnętrzni partnerzy, od których organizacja zależy: dostawcy oprogramowania, sprzętu i usług. **Atak na łańcuch dostaw polega na zaatakowaniu słabiej chronionego ogniwa, żeby przez nie dostać się do właściwego celu**, albo do wielu celów naraz. To podobna logika jak w opisanym niżej ataku [Watering hole](#watering-hole): skoro cel jest dobrze chroniony, atakujemy kogoś, komu cel ufa.
## Managed service providers (MSPs)
**Dostawcy usług zarządzanych** (ang. *Managed Service Providers*, MSP) to firmy, które zarządzają infrastrukturą IT innych firm: serwerami, siecią, kopiami zapasowymi czy bezpieczeństwem. Aby to robić, mają **szeroki, uprzywilejowany dostęp** (ang. *privileged access*) **do systemów wielu klientów jednocześnie**. Dla atakującego to łakomy kąsek: przejęcie jednego MSP otwiera drzwi do wszystkich jego klientów.

Przykładem jest atak z lipca 2021 r. na oprogramowanie **Kaseya VSA** (nazwa produktu, pierwotnie od ang. *Virtual System Administrator*), służące MSP do zdalnego zarządzania komputerami klientów. Grupa ransomware REvil wykorzystała lukę w tym oprogramowaniu i przez dostawców usług zaszyfrowała komputery w setkach firm na całym świecie.
## Vendors
**Dostawcy** (ang. *vendors*), czyli firmy, od których kupujemy produkty, przede wszystkim oprogramowanie. Ufamy, że aktualizacja od znanego producenta jest bezpieczna, i instalujemy ją automatycznie. Jeśli jednak atakujący przejmie proces tworzenia oprogramowania u producenta, **złośliwy kod trafia do klientów razem z oficjalną, podpisaną aktualizacją** (ang. *signed update*).

Najgłośniejszym przykładem jest atak na firmę **SolarWinds** wykryty pod koniec 2020 r. Do aktualizacji popularnego systemu monitorowania sieci Orion włączono tylną furtkę (ang. *backdoor*), a zainfekowaną wersję pobrało około 18 tys. klientów, w tym agencje rządowe USA. Atak przypisano rosyjskiemu wywiadowi.

Dostawcą jest też partner, któremu dajemy dostęp do swoich systemów. W głośnym włamaniu do amerykańskiej sieci sklepów **Target** (2013) przestępcy weszli do sieci przy użyciu danych logowania firmy zajmującej się klimatyzacją i wentylacją w sklepach, a następnie wykradli dane kart płatniczych milionów klientów.
## Suppliers
**Dostawcy komponentów** (ang. *suppliers*) dostarczają *części*, z których zbudowane są nasze produkty i systemy: podzespoły sprzętowe, firmware, a także biblioteki i pakiety open source wykorzystywane w oprogramowaniu. Zagrożenia z tej strony to m.in.:
- **podrobiony lub zmodyfikowany sprzęt** – urządzenia sieciowe czy podzespoły z nieznanego źródła mogą zawierać ukryte modyfikacje;
- **złośliwy kod w bibliotekach open source** – w 2024 r. wykryto tylną furtkę w popularnej bibliotece kompresji **xz utils** ([CVE-2024-3094](https://www.cve.org/CVERecord?id=CVE-2024-3094)), wprowadzoną przez osobę, która przez dwa lata budowała zaufanie jako współopiekun projektu (ang. *maintainer*). Na szczęście furtkę wykryto, zanim trafiła do stabilnych wydań większości popularnych dystrybucji Linuksa (zdążyła pojawić się m.in. w wersjach testowych Debiana i Fedory).

Obrona przed atakami na łańcuch dostaw jest trudna, bo z definicji dotyczy podmiotów, którym ufamy. Organizacje stosują m.in. ocenę bezpieczeństwa dostawców (ang. *vendor assessment*) przed podpisaniem umowy, ograniczanie ich uprawnień do niezbędnego minimum (zasada najmniejszych uprawnień, ang. *least privilege*), monitorowanie ich dostępu oraz spis komponentów oprogramowania (ang. *Software Bill of Materials*, SBOM).
# Human vectors/social engineering
Bardzo często najsłabszym ogniwem całego systemu bezpieczeństwa jest jego użytkownik, czyli człowiek. Właśnie dlatego ataki wykorzystujące **inżynierię społeczną** (lub inaczej **socjotechnikę**) są bardzo często stosowane - ponieważ są skuteczne.

**Inżynieria społeczna to złożone techniki manipulacji oparte na psychologii, stosowane w celu wyłudzenia informacji lub nakłonieniu do realizacji określonych działań**. Głównym celem inżynierii społecznej nie jest zmuszanie ludzi do robienia tego, czego nie chcą, ale wskazanie im kierunku, w którym oni sami podążą z przekonaniem o słuszności swojego wyboru.
## Phishing
**Jedna z najpopularniejszych metod oszustwa polegająca na podszywaniu się pod zaufaną instytucję lub osobę (np. bank, firmę kurierską czy osobę publiczną) celem nakłonienia ofiary do wykonania jakiejś czynności z korzyścią dla atakującego**.

Przykładowo, możemy dostać maila, który wygląda niemalże identycznie jak wiadomość z naszego banku i który informuje nas o konieczności natychmiastowej zmiany hasła do naszej bankowości internetowej, ponieważ _wykryto próby włamania się na nasze konto_. W mailu znajduje się link, który po kliknięciu przekieruje nas na stronę przypominającą stronę logowania do naszego systemu bankowego. Niestety, jest to witryna podstawiona przez oszustów, a my właśnie przekazaliśmy im nieświadomie nasze dane logowania.

Istnieje wiele odmian phishingu, ale aktualnie najpopularniejszym kanałem dystrybucji jest **email**. Jeśli mamy odrobinę szczęścia takie maile są wykrywane przez filtry antyspamowe, ale nie zawsze. Atakujący mogą wiedzieć z jakich usług zazwyczaj korzystamy i będzie próbował podszyć się pod naszych zaufanych usługodawców. Często nasilenie takich ataków następuje przy okazji ważnych wydarzeń, np. przy okazji inwazji Rosji na Ukrainę (24.02.2022) możemy spodziewać się wzrostu liczby wiadomości z linkami do fałszywych zbiórek pieniędzy na uchodźców.

Na szczęście jeśli jesteśmy czujni, istnieje małe prawdopodobieństwo, że damy złapać się na haczyk. Zawsze powinniśmy zwracać uwagę na następujące elementy i jeśli coś nam się nie zgadza, w naszej głowie od razu powinna zawyć syrena alarmowa:

- **Czy adres mailowy nadawcy jest prawidłowy i czy nie ma w nim żadnych _literówek_?** Oczywiście, nawet jeśli adres jest prawidłowy nie powinniśmy opuszczać gardy, ponieważ ktoś mógł się podszyć pod prawdziwy adres za pomocą bardziej wyrafinowanych technik.
- **Czy link zawarty w mailu jest prawidłowym adresem URL naszego usługodawcy?** Przeważnie adresy URL w przypadku oszustwa wyglądają bardzo podobnie do tych prawdziwych, ale różnią się jakimś szczegółem, takim jak literówka w nazwie domeny czy inna nazwa domeny (np. _mbank.net.pl_ zamiast _mbank.pl_). Pamiętajmy jednak, żeby bardzo dokładnie przyjrzeć się adresowi URL, bo może wyglądać niemalże identycznie jak ten oryginalny (patrz [Atak Homograficzny](http://www.crypto-it.net/pl/ataki/atak-homograficzny.html)), **a najlepiej po prostu wpisać ręcznie prawidłowy adres w pasku przeglądarki**.
- Kiedy już kliknęliśmy link to sprawdźmy czy nic na stronie nie wzbudza naszych podejrzeń – mogą to być np. inne czcionki niż te, które pamiętamy lub inaczej wyglądająca szata graficzna.
## Vishing
**Vishing (*voice phishing*) to inaczej phishing za pośrednictwem komunikacji głosowej(telefonicznej oraz VoIP)**. Dzwoniący oszust, podając się za kogoś kim nie jest, za pomocą technik socjotechnicznych, próbuje wyciągnąć od ofiary wrażliwe informacje.

Przykład popularnego ostatnimi czasy działania: [Policjanci publikują rozmowę z fałszywym pracownikiem banku. Nagranie ku przestrodze](https://www.youtube.com/watch?v=H64veR-Tgjs).
## Smishing
**Smishing (SMS phishing) to rodzaj phishingu skierowany na wiadomości SMS (*Short Message Service*)**. Zasady są podobne do tych opisanych wyżej, z tą różnicą, że fałszywe wiadomości są przesyłane za pośrednictwem protokołu SMS.

W tym przypadku atakujący może również podszyć się pod prawdziwy numer telefonu ([Spoofing rozmów telefonicznych](https://niebezpiecznik.pl/post/spoofing-rozmow-telefonicznych/)). Dodatkowo, dużo łatwiej jest wygenerować istniejący numer telefonu niż istniejący adres email, ponieważ liczba możliwych numerów telefonu jest bardziej ograniczona niż liczba prawidłowych adresów email.
## Misinformation/disinformation
TBD
## Impersonation
W dosłownym tłumaczeniu jest **to udawanie kogoś innego niż się jest w rzeczywistości** i stanowi absolutną podstawę udanego ataku socjotechnicznego. Często atakujący podszywa się pod personę, która stoi wyżej w hierarchii organizacji niż osoba atakowana. Jest to czynnik psychologiczny, który może wywierać dodatkową presję na ofiarę i przez to będzie łatwiej nakłonić ją do zrobienia tego czego chce oszust.
## Business email compromise
TBD
## Pretexting
Atakujący musi mieć dobry **pretekst**, żeby nakłonić swoją ofiarę do ujawnienia cennych informacji. Innymi słowy, musi wymyślić naprawdę zgrabną i wiarygodną bajeczkę, żeby ofiara w nią uwierzyła. Starannie przeprowadzony rekonesans owocuje nawet kilkoma scenariuszami.

**Atakujący może często posługiwać się technicznym żargonem, żeby jeszcze bardziej uwiarygodnić swoją historię**. Aby utrudnić opracowanie dobrego pretekstu musimy być świadomi tego, co publikujemy w Internecie. Pozornie nieszkodliwe informacje umieszczane w mediach społecznościowych mogą posłużyć do opracowania naprawdę wiarygodnej historyjki.

Przykładowe preteksty:
- *Dzień dobry, nazywam się Danuta Norek i dzwonię z Banku Centralnego Wakandy. Wykryliśmy na Pani koncie podejrzaną aktywność i tymczasowo zablokowaliśmy środki celem weryfikacji. Czy mogłaby Pani zalogować się do swojego banku przez link, który przed chwilą został wysłany i potwierdzić, że operacja została zlecona przez Panią?*
- *Cześć, Karol! Dzwonię z 3-go piętra, z działu IT._ _Marek_ (atakujący wie, że tak ma na imię menadżer Karola) _prosił mnie, żebym zresetował hasła w Waszym zespole, bo okazało się, że komunikacja między usługami AWS, a naszym serwerem Kerberos była po HTTP zamiast po HTTPS i byliśmy narażeni na sniffing. Czy mógłbyś zresetować swoje hasło przez link, który zaraz Tobie wyślę?*
- *Jesteś 1000 osobą, która odwiedziła tę witrynę, w związku z tym przygotowaliśmy dla Ciebie małą niespodziankę. Wystarczy, że wypełnisz ten formularz…*
## Watering hole
Jeśli organizacja jest bardzo dobrze chroniona (tj. infrastruktura nie ma żadnych znanych podatności, wdrożone polityki bezpieczeństwa są dobrze przemyślane i respektowane, członkowie są dobrze przeszkoleni oraz świadomi zagrożeń), atakujący ma bardzo nikłe szanse powodzenia w bezpośrednim ataku. W takim przypadku jest zmuszony zmienić strategię i zastosować technikę, którą można przetłumaczyć jako *zatruty wodopój* bądź atak *u wodopoju* (ang. ***watering hole attack***).

**Ta strategia polega na określeniu miejsca, poza atakowaną organizacją, gdzie zazwyczaj gromadzą się i przebywają jej członkowie**. Może to być miejsce fizyczne, takie jak kawiarnia chociaż częściej jest to zewnętrzny serwis internetowy (***third party***).

**Kolejnym krokiem jest atak na zidentyfikowany cel pośredni, który jest słabiej chroniony. Polega zazwyczaj na zainfekowaniu strony złośliwym oprogramowaniem, dzięki czemu istnieje duże prawdopodobieństwo, że członkowie organizacji również zostaną zainfekowani i da to atakującemu upragniony dostęp do instytucji docelowej**.

Aby uniknąć wczesnego wykrycia atakujący często próbuje zainfekować jedynie wąską grupę odwiedzających skompromitowaną stronę, np. infekując tylko użytkowników z określonymi adresami IP, związanych z docelowo atakowaną organizacją.

Przykładem takiego ataku z naszego podwórka jest atak na instytucje bankowe w Polsce, gdzie prawdopodobnym źródłem złośliwego oprogramowania był serwer Komisji Nadzoru Finansowego (KNF), który jest często odwiedzany przez pracowników bankowości. Więcej informacji o tym ataku można znaleźć w sieci, na przykład w artykule [Poważny atak na polskie banki mniej tajemniczy](https://www.benchmark.pl/aktualnosci/powazny-atak-na-polskie-banki-mniej-tajemniczy.html).
## Brand impersonation
TBD
## Typosquatting
**Metoda oszukiwania użytkowników wykorzystująca typowe błędy literowe w adresach URL**. Innym określeniem tej metody jest ***URL hijacking***. Technika wykorzystuje nieuwagę użytkownika oraz fakt, że podstawiony adres z literówką wygląda bardzo podobnie do oryginalnego.

Przykładem jest domena _**google.com**_, gdzie użytkownik może w pośpiechu wpisać błędny adres ***gogole.com***. Akurat w tym przypadku zostajemy przekierowani na oryginalny adres wyszukiwarki, ale w innych okolicznościach możemy mieć mniej szczęścia, bo **_typosquatting_** jest często wykorzystywany do ataków phishingowych.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [Czym jest PHISHING i jak nie dać się nabrać na podejrzane wiadomości e-mail oraz SMS-y?](https://www.gov.pl/web/baza-wiedzy/czym-jest-phishing-i-jak-nie-dac-sie-nabrac-na-podejrzane-widomosci-e-mail-oraz-sms-y)
- [CERT Polska: Zewnętrzna powierzchnia ataku](https://wiedza.cert.pl/odpornosc-infrastruktury/zewnetrzna-powierzchnia-ataku/zewnetrzna-powierzchnia-ataku/)
- [CERT Polska: Fałszywe załączniki](https://cert.pl/falszywe-zalaczniki)
- [NIST SP 800-161 Rev. 1: Cybersecurity Supply Chain Risk Management Practices](https://csrc.nist.gov/pubs/sp/800/161/r1/upd1/final)
