# 2.4 Given a scenario, analyze indicators of malicious activity
Na podstawie podanego scenariusza, zidentyfikuj i przeanalizuj czynniki wskazujące na złośliwe działania.
# Malware attacks
***Malicious software* (w skrócie *malware*), czyli złośliwe/szkodliwe oprogramowanie, definiuje ogół programów komputerowych, których celem jest zazwyczaj wyrządzenie szkód w systemie komputerowym oraz działanie na niekorzyść jego użytkowników**.

Pamiętajmy jednak, że programista to też człowiek i zdarza się jemu (lub jej) popełniać błędy, więc może dojść do sytuacji, gdzie aplikacja *niechcący narozrabia*. Oprogramowanie zawierające niezamierzone błędy (ang. *bugs*), które mogą spowodować nieplanowane szkody, nie podpada pod definicję złośliwego oprogramowania.

Istnieje wiele odmian złośliwego oprogramowania. Jedne umożliwiają zdalny dostęp do zainfekowanego systemu, inne zbierają wrażliwe dane, a jeszcze inne robią *rozpierduchę* w systemie plików.

Jak zapewne zauważycie, prawie wszystkie przedstawione niżej kategorie nachodzą na siebie w dużym stopniu. Przykładowo, w większości przypadków *ransomware* (dosłownie: program szantażujący) jest jednocześnie złośliwym oprogramowaniem szyfrującym - *cryptomalware*. Wiele wymienionych tutaj rodzajów posiada też cechy wirusa komputerowego. 

Prawdopodobne jest również ryzyko, że infekcja jednym rodzajem oprogramowania może skutkować instalacją kolejnych typów. Przykładowo, nasz system może mieć podatność (ang. *vulnerability*), którą wykorzystuje jakiś robak (*worm*). Kiedy ten dostanie się do systemu i zainstaluje bez naszej wiedzy *tylną furtkę* (*backdoor*), ktoś nam nieprzychylny (dajmy na to twórca robaka) ma od teraz zdalny dostęp do naszej maszyny. W tym momencie możliwe jest zdalne ściągnięcie i uruchomienie kolejnej porcji złośliwego kodu, który na przykład zaszyfruje nasze dane (*ransomware*) lub przyłączy nas do sieci *botnet*.
## Ransomware
W dobie powszechnej cyfryzacji, dane, które posiadamy mogą być dla nas bardzo cenne. Ważne dokumenty zapisane na dysku, nagrania z dorastającym dzieckiem czy nawet zdjęcia z wakacji są dla nas często wartościowym zasobem, którego utrata może bardzo mocno zaboleć. Nie wspominając o danych firm i innych organizacji, których utrata może doprowadzić nawet do wielomilionowych strat finansowych. Mowa tutaj o tajnych informacjach dotyczących strategii, danych osobowych klientów i pracowników (PII = *Personally Identifiable Information*) czy też danych finansowych.

Niestety, cyberprzestępcy zorientowali się, że niektórzy są w stanie słono zapłacić, żeby tylko nie utracić swoich wartościowych danych. Tak właśnie narodziło się ***ransomware*, czyli złośliwe oprogramowanie blokujące użytkownikowi dostęp do jego danych i żądające zapłaty w zamian za odblokowanie tych danych**. **Innymi słowy, jest to żądanie okupu (ang. *ransom*) w zamian za odzyskanie dostępu do swoich zasobów**. W dosłownym tłumaczeniu jest to *oprogramowanie szantażujące* lub *oprogramowanie wymuszające okup*.

Sposób działania takiego oprogramowania może być bardzo różny. Zazwyczaj jest to trojan lub robak (ang. *worm*), który dostaje się do systemu operacyjnego przez naszą nieuwagę lub niezałataną lukę bezpieczeństwa, a następnie próbuje zablokować dostęp do systemu i danych. Jednocześnie informuje nas, że trzeba będzie, kolokwialnie mówiąc, *wyskoczyć z kasy*.

Oprócz odpowiedniej techniki uniemożliwienia dostępu do danych, bardzo istotnym elementem (jeśli nie najważniejszym) jest bezpieczny dla atakującego oraz trudny do namierzenia system płatności. W związku z tym często wykorzystuje się wiadomości SMS o podwyższonej opłacie; rozwiązania typu *pre-paid* (np. [paysafecard](https://www.paysafecard.com/)) czy też popularną kryptowalutę Bitcoin (podobno niektóre firmy nawet [gromadzą środki w postaci Bitcoinów w ramach planu awaryjnego](https://bravenewcoin.com/insights/large-uk-businesses-holding-bitcoin-to-pay-ransoms)).

To w jaki sposób użytkownik zostaje *odcięty* od swoich plików zależy od rodzaju *ransomware’u*. Najprostszą formą jest założenie prostej blokady na system i wyświetlenie użytkownikowi odpowiedniej informacji o konieczności zapłaty (np. *organy ścigania Policji wykryły na tym komputerze nielegalne oprogramowanie i w związku z tym komputer został zablokowany – prosimy o uiszczenie grzywny w wysokości 1000 zł celem odblokowania systemu*).

Zazwyczaj blokada systemu polegała na podmianie ścieżki do powłoki systemu Windows (ang. *[Windows shell](https://en.wikipedia.org/wiki/Windows_shell)*), czyli bazowym programie uruchamianym tuż po zalogowaniu się użytkownika i odpowiadającym za graficzny interfejs systemu (m.in. pulpit, pasek zadań). Jeśli uruchomimy edytor rejestru systemowego (*regedit.exe*) w jednym z nowszych systemów Windows i przejdziemy do klucza `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`, zobaczymy, że ten ma wartość `explorer.exe`. Oznacza to, że aktualną powłoką systemową jest program *[Windows File Explorer](https://en.wikipedia.org/wiki/Windows_File_Explorer)*, ale można go podmienić na inny, na przykład taki co blokuje pełne uruchomienie systemu i żąda okupu.

W skrajnych przypadkach, oprogramowanie typu *ransomware* może przyjąć formę wspomnianego wcześniej *wirusa dyskowego* i zmodyfikować główny sektor rozruchowy na dysku. W takim przypadku system operacyjny w ogóle nie będzie w stanie prawidłowo wystartować.

Stosunkowo często zdarzało się, że blokady opisane powyżej można było zdjąć, bez utraty danych, jeśli posiadało się odpowiednią wiedzę techniczną. Nawet jeśli trzeba było sformatować cały dysk celem usunięcia zainstalowanego szkodnika, to mieliśmy dostęp do naszych danych choćby za pośrednictwem systemów typu [Live CD](https://en.wikipedia.org/wiki/Live_CD) (system operacyjny na zewnętrznym nośniku danych, posiadający swój własny program rozruchowy)**. Kiedy jednak przestępcy zorientowali się, że zwykłe oszustwa ([*hoax*](https://vilya.pl/sy0-601-cheatsheet-1-1-social-engineering/#hoax)) oraz względnie proste metody blokowania dostępu do systemu stały się niewystarczające, sięgnęli po broń cięższego kalibru. Zaczęli szyfrować dane, żądając zapłaty za ich odszyfrowanie** – tak powstała kolejna forma złośliwego oprogramowania, czyli ***cryptomalware***.
## Trojan
*Timeo Danaos et dona ferentes*, czyli po łacińsku: *obawiam się Greków, nawet gdy przynoszą dary*. Tak napisał rzymski poeta Wergiliusz w swoim poemacie *Eneida*, nawiązując do fortelu przygotowanego przez Greków podczas wojny trojańskiej. Chodzi oczywiście o słynnego ***konia trojańskiego***, czyli drewnianą konstrukcję w kształcie konia, w której ukryli się greccy wojownicy, zaraz po pozornym wycofaniu się z oblężenia Troi. Obrońcy miasta, nie spodziewając się podstępu, wciągnęli konia za mury co ostatecznie doprowadziło do ich klęski. Ukryci w drewnianym koniu żołnierze otworzyli nocą bramy, tym samym umożliwiając Grekom zdobycie miasta.

Niezależnie od tego czy koń trojański istniał naprawdę, czy jest to tylko fikcja literacka, stał się tak popularny, że dzisiaj jest synonimem podarunku skrywającego zgubę i podstęp. W świecie IT określenie ***koń trojański*** (lub w skrócie ***trojan***), ma identyczne znaczenie. **Jest to złośliwe oprogramowanie, które podszywa się pod użyteczne bądź ciekawe aplikacje, ukrywając przed użytkownikiem swoje szkodliwe funkcje**. Krótko mówiąc, kiedy wydaje nam się, że właśnie instalujemy fajną grę komputerową, być może właśnie autoryzowaliśmy bezwiednie instalację złośliwego oprogramowania w naszym systemie. Co więcej, gra rzeczywiście może się uruchomić, ale równocześnie został wykonany złośliwy kod, który jest w stanie nam zaszkodzić w ten czy inny sposób.

Typowe zagrożenia związane z działalnością trojanów są następujące:
- Ukrywanie się przed oprogramowaniem antywirusowym bądź jego całkowita neutralizacja. To samo tyczy się pozostałych programów zabezpieczających (np. firewall).
- Instalacja *tylnej furtki* (ang. *backdoor*) w systemie, w celu umożliwienia bezpośredniego dostępu do zainfekowanej maszyny nieuprawnionej osobie bądź aplikacji. Dzięki takiej furtce atakujący jest w stanie uzyskać dostęp do systemu bez procesu uwierzytelnienia, co z kolei umożliwia przyłączenie zaatakowanej stacji roboczej do sieci botnet, która rozsyła spam lub przeprowadza ataki DDoS (ang. *Distributed Denial of Service*).
- Wyświetlanie niechcianych reklam, np. poprzez podmianę strony startowej w przeglądarkach internetowych lub instalację oprogramowania typu *[adware](https://en.wikipedia.org/wiki/Adware)*.
- Instalacja oprogramowania szpiegującego (ang. *spyware*) oraz wykradanie poufnych danych użytkownika.
- Działania destrukcyjne, takie jak usuwanie plików czy szyfrowanie danych (*ransomware/cryptomalware*).
- Instalacja innych typów złośliwego oprogramowania.
## Worm
## Spyware
## Bloatware
## Virus
## Keylogger
## Logic bomb
## Rootkit
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)