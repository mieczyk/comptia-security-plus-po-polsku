# 2.2 Explain common threat vectors and attack surfaces
Na egzaminie należy wykazać się znajomością i zrozumieniem przedstawionych poniżej zagrożeń i wektorów ataku.
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