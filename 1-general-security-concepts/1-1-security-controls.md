# 1.1 Compare and contrast various types of security controls
*Porównaj ze sobą i wskaż różnice pomiędzy różnymi formami kontroli bezpieczeństwa, których zadaniem jest zapobieganie, wykrywanie oraz minimalizowanie skutków różnych typów zagrożeń.*

Termin ***security controls*** można przetłumaczyć jako **środki bezpieczeństwa** lub **formy kontroli bezpieczeństwa**. Są to **wszelkiego rodzaju środki, których zadaniem jest szeroko pojęta ochrona organizacji wraz z jej zasobami (fizycznymi oraz wirtualnymi), polegająca na minimalizacji lub eliminacji ryzyka wystąpienia incydentów bezpieczeństwa**. Mówiąc inaczej, *security controls* są częścią, a właściwie rezultatem, procesu zarządzania ryzykiem i mają na celu zminimalizowanie lub całkowite wyeliminowanie (o ile to możliwe) potencjalnych zagrożeń.

Implementacja skutecznych środków bezpieczeństwa nie jest zadaniem trywialnym. Żeby sprostać temu zadaniu, organizacja powinna mieć jasno zdefiniowany profil ryzyka, który opisuje jakie potencjalne zagrożenia mogą jej zaszkodzić. Poza tym, należy zestawić ze sobą koszty wdrożenia wymaganych środków zapobiegawczych wraz z potencjalnymi kosztami wystąpienia incydentów i na podstawie takiej kalkulacji dobrać odpowiedni zestaw rozwiązań. 

Pamiętajmy, że zagrożenia (zewnętrzne oraz wewnętrzne), przed którymi chcemy chronić naszą organizację, wcale nie muszą być wynikiem działań z premedytacją. Potencjalnym niebezpieczeństwem może być również nieuważny pracownik, który przez nieuwagę doprowadza do wycieku danych, a także pożar w serwerowni oraz katastrofy naturalne.

Poniżej znajduje się często spotykany, choć nie do końca zestandaryzowany, podział różnych form kontroli bezpieczeństwa, obowiązujący na egzaminie CompTIA Security+. Warto przy tym pamiętać, że nie są to *sztywne* ramy i różne organizacje mogą inaczej podchodzić do klasyfikacji popularnych środków bezpieczeństwa, bo niektóre z nich mogą jednocześnie *wpadać* w różne kategorie (jak zauważymy na przykładach poniżej). Niestety, **na egzaminie musimy trafić w klucz odpowiedzi, więc postarajmy się zapamiętać kluczowe cechy (ang. *key indicators*) każdej z opisanych niżej kategorii i zawsze wybierajmy tę odpowiedź, która pasuje *bardziej* niż pozostałe**.
# Categories
W zależności od tego, do którego obszaru organizacji się odnosimy (zasoby cyfrowe, personel, fizyczny dostęp do budynku) lub na jakim poziomie działamy (od administracyjnego po *stricte* techniczny), formy kontroli bezpieczeństwa można podzielić na kategorie opisane poniżej.
## Technical
**Metody kontroli na poziomie ściśle technicznym, których zadaniem jest ochrona danych oraz systemów IT** w organizacji (*software* oraz *hardware*). Do tej kategorii zaliczamy m.in. firewalle; oprogramowanie antywirusowe; systemy wykrywania włamań IDS (*Intrusion Detection System*) oraz systemy zapobiegające włamaniom IPS (*Intrusion Prevention System*); rozwiązania DLP (*Data Loss Prevention*). Krótko mówiąc, **te środki bezpieczeństwa skupiają się na wykorzystaniu technologii IT do ochrony zasobów IT**.
## Managerial
*Managerial security controls* (choć częściej można spotkać się z terminem *administrative security controls*) jest **kategorią określającą mechanizmy kontrolne na poziomie administracyjnym/kierowniczym**, czyli abstrakcyjnie *wyższym* niż wspomniana wcześniej kategoria *stricte* techniczna.

W ramach tego zakresu możemy wymienić **polityki** (ang. *policies*), **procedury** (ang. *procedures*) oraz **wytyczne** (ang. *guidelines*), które powinny być dobrze udokumentowane, a także respektowane i stosowane przez personel organizacji, celem zapewnienia pożądanego poziomu bezpieczeństwa. Przykład: spisany proces wdrażania nowego pracownika (*onboarding*), czy też dokument z zaleceniami bezpieczeństwa, z którym powinien zapoznać się każdy pracownik.
## Operational
**W tej kategorii główną rolę odgrywa człowiek, zamiast zautomatyzowanych systemów** (według [słownika NIST](https://csrc.nist.gov/glossary/term/operational_controls)). Przykładem takich środków bezpieczeństwa są pracownicy ochrony, a także szkolenia bądź programy budowania świadomości wśród pracowników.
## Physical
Jak sama nazwa wskazuje, ta **kategoria obejmuje zabezpieczenia chroniące przed fizycznym dostępem przez osoby nieuprawnione** do terenu, budynku, pojedynczego pokoju (np. serwerowni), sprzętu, a nawet dokumentów danej organizacji. Przykład: budki wartownicze (ang. *guard shack*); ogrodzenia; zamki w drzwiach; czytniki kart dostępu; kamery; systemy alarmowe.
# Control types
Innym rodzajem podziału środków bezpieczeństwa jest **podział ze względu na pełnioną funkcję**. Jak zauważymy w poniższych przykładach, środki o konkretnym przeznaczeniu stosujemy do ochrony różnych poziomów organizacji, które zostały opisane powyżej. Działa to również w drugą stronę: określony obszar może być chroniony przez narzędzia pełniące różne funkcje.
## Preventive
**Grupa środków prewencyjnych pełniących, zgodnie z swoją nazwą, funkcję zapobiegawczą. Ich zadaniem jest blokowanie wszelkich prób nieautoryzowanego dostępu, zarówno do zasobów cyfrowych, jak i fizycznych.**

Mogą to być reguły firewalla blokujące dostęp do wybranych zasobów sieciowych, ale także zamki elektroniczne w drzwiach. Czyli *de facto* wszystko, co skutecznie zablokuje jakąkolwiek próbę nieautoryzowanego dostępu do chronionego zasobu.
### Przykłady
- ***Technical***: 
	- Firewalle - sprzętowe i programowe.
	- Oprogramowanie antywirusowe i generalnie *anti-malware*.
	- Systemy IPS, zapobiegające włamaniom.
- ***Managerial***:
	- Systemowa i dobrze udokumentowana procedura wdrażania nowego pracownika (ang. *onboarding*) - dzięki temu *świeżo upieczony* pracownik będzie w stanie uniknąć fatalnych w skutkach pomyłek, które mogą wynikać z nieznajomości wszystkich procedur obowiązujących w organizacji (co jest naturalne na początku współpracy).
	- Systemowa i dobrze udokumentowana procedura zakończenia współpracy z pracownikiem odchodzącym z firmy (ang. *offboarding*) - w tym przypadku organizacja jest w stanie zapobiec m.in. nieświadomym (lub świadomym, jeśli zwolniony pracownik chowa urazę) wyciekom danych.
- ***Operational***:
	- Budka wartownicza (ang. *guard shack*) lub pracownik ochrony pilnujący wejścia do budynku.
- ***Physical***:
	- Ogrodzenie wokół terenu organizacji (ang. *fence*).
	- Zamki w drzwiach (ang. *locks*), zarówno mechaniczne (na klucz), jak i elektroniczne (na kartę dostępu lub z skanerem biometrycznym).
	- Pachołki/słupki pełniące rolę blokady, uniemożliwiającej przejazd pojazdów (ang. *bollards*).
## Deterrent
Rolą tych środków bezpieczeństwa jest **zniechęcanie (ang. *deter*) i odstraszanie potencjalnego intruza poprzez dobitne wskazanie ewentualnych konsekwencji uzyskania nieautoryzowanego dostępu do strzeżonych zasobów**. Pamiętajmy, że narzędzia z tej kategorii same w sobie nikogo nie powstrzymają, ale mogą sprawić, że ewentualny włamywacz zastanowi się dwa razy przed kontynuacją swoich działań.

Może się to okazać wystarczające, szczególnie jeśli ostrzegana osoba nie ma złych zamiarów. Przykładowo, ktoś przez pomyłkę otrzymał maila z poufnymi informacjami (nadawca pomylił adres odbiorcy) - ostrzeżenie w stopce o konsekwencjach prawnych wykorzystania tych danych zazwyczaj wystarczy, żeby omyłkowy odbiorca po prostu usuną tę wiadomość i powiadomił nadawcę o pomyłce.
### Przykłady
- ***Technical***:
    - Ekran powitalny (ang. *splash screen*), wyświetlający się na ekranie komputera lub urządzenia mobilnego, który informuje o tym, że dalszy dostęp do systemu jest przeznaczony jedynie dla uprawnionych użytkowników. Jeśli użytkownik takich uprawnień nie posiada, powinien zaniechać dalszych działań, pod groźbą konsekwencji prawnych.
    - [Baner ostrzegawczy](https://www.tecmint.com/ssh-warning-banner-linux/) przeznaczony dla użytkowników logujących się przez SSH.
- ***Managerial***:
    - Stopka w mailu, ostrzegająca, że jeśli odbiorca nie jest uprawniony do odczytania/przetwarzania otrzymanych informacji, winien jest natychmiast skasować.
    - Zapiski w umowie z pracownikiem, w których zawarte są potencjalne konsekwencje nieuprawnionego wykorzystania dostępnych informacji. Karą za naruszenie warunków umowy może być degradacja, zwolnienie dyscyplinarne, kara finansowa, a nawet postawienie zarzutów karnych.
- ***Operational***:
    - Recepcja znajdująca się przy wejściu do firmy. W odróżnieniu od ochrony przy wejściu, rolą recepcjonisty bądź recepcjonistki nie jest powstrzymanie intruza. Jeśli jednak sama obecność pracowników recepcji nie powstrzyma nieproszonego gościa, mogą oni powiadomić ochronę o incydencie (choć kiedy to nastąpi, funkcja recepcji zmienia się z *deterrent* na *detective/corrective* :)).
- ***Physical***:
    - Znaki ostrzegawcze typu *nieupoważnionym wstęp wzbroniony* (ang. *restricted area*), wraz z informacją o potencjalnych konsekwencjach złamania zakazu.
## Detective
Formy kontroli bezpieczeństwa pełniące **funkcję wykrywającą i ostrzegawczą**. Ich celem jest poinformowanie o incydencie bezpieczeństwa, który już miał miejsce.

Warto przy okazji wspomnieć, że analiza alarmów wszczętych przez tę grupę środków może znacząco wpływać na udoskonalenie środków prewencyjnych (*preventive*).
### Przykłady
- ***Technical***:
	- Rozwiązania typu [SIEM](https://kapitanhack.pl/2019/06/26/akronimy/czym-jest-siem/) (*Security Information and Event Management*), agregujące logi związane z bezpieczeństwem z różnych części systemu.
	- Systemy wykrywania włamań (IDS). W odróżnieniu od wspomnianych wcześniej systemów IPS, ich zadaniem jest wykrycie podejrzanych aktywności i powiadomienie o tym administratorów, a nie czynne przeciwdziałanie.
- ***Managerial***:
	- Regularny przegląd ról i praw dostępu nadanych użytkownikom - czy niektórzy z nich nie mają zbyt szerokich uprawnień?
	- Regularny przegląd raportów zawierających informacje o aktywności kont użytkowników - czy w logach nie ma jakichś podejrzanych operacji logowania się na konto? Na przykład z adresu IP wskazującego na odległy kraj, pomimo tego, że dany użytkownik cały czas pracuje z biura.
- ***Operational***:
	- W tym przypadku również sprawdzą się pracownicy ochrony, którzy wykonują regularne obchody po obiekcie i podczas rutynowej inspekcji mogą natknąć się na ślady włamania (np. przecięta siatka ogrodzenia bądź wyłamany zamek w drzwiach).
- ***Physical***:
	- Detektory ruchu.
	- Kamery przemysłowe CCTV (*Closed Circuit Television*).
	- Drony zwiadowcze.
	- Czujniki dymu (pamiętajmy, że zagrożeniem mogą być nie tylko intruzi).
## Corrective
**Środki naprawcze/korygujące stosowane po wystąpieniu incydentu**. Ich zadaniem jest minimalizacja lub całkowite usunięcie skutków zdarzenia, a także zapewnienie ciągłości działania organizacji oraz jej systemów.
### Przykłady
- ***Technical***: 
	- Usunięcie bądź kwarantanna zarażonych plików. Innymi słowy, pozbycie się [złośliwego oprogramowania](https://vilya.pl/comptia-security-1-2-1-malware/) (*malware*) z systemów organizacji.
	- Instalacja poprawek bezpieczeństwa w oprogramowaniu, które eliminują wykorzystaną podatność.
	- Przywrócenie danych z kopii zapasowych (ang. *backup*). Przykładowo, kiedy ważne pliki zostały zaszyfrowane przez [*ransomware*](https://vilya.pl/comptia-security-1-2-1-malware/#ransomware), jest duża szansa, że musimy się z nimi pożegnać (zakładając, że nie planujemy płacić okupu). Dlatego tak bardzo ważne jest regularne tworzenie kopii zapasowych danych organizacji. Dzięki temu, po pozbyciu się infekcji i *załataniu dziur*, będziemy w stanie przywrócić utracone informacje.
- ***Managerial***:
	- Polityka zgłaszania incydentów bezpieczeństwa bądź podejrzanych aktywności.
	- Udokumentowane procedury reagowania na incydenty bezpieczeństwa.
	- Plan zapewniający ciągłość działania organizacji (ang. *business continuity plan*) po wystąpieniu poważnego incydentu.
- ***Operational***:
	- Pracownicy ochrony, kiedy są zmuszeni do wyprowadzenia nieupoważnionej osoby z terenu organizacji i/lub zawiadomienia policji.
- ***Physical***:
	- Gaśnica (ang. *fire extinguisher*).
	- Spryskiwacze przeciwpożarowe (ang. *fire sprinkles*).
## Compensating
Czasami zdarza się, że nie jesteśmy w stanie całkowicie wyeliminować zagrożenia, a co gorsza, zastosowanie środków naprawczych (*corrective*) również jest poza naszym zasięgiem (np. ze względów finansowych).  W takim wypadku, naszą opcją będą **środki kompensacyjne, które same w sobie nie rozwiązują pierwotnego problemu, ale pozawalają go *obejść* (nawet tymczasowo).** Krótko mówiąc, są to **alternatywne środki zastępcze**, które stosujemy, jeśli nie jesteśmy w stanie zapobiec zagrożeniom lub naprawić skutków incydentu z użyciem standardowych i dedykowanych metod, opisanych powyżej.

 Dobrym przykładem jest system [HVAC](https://www.klimatyzacja.pl/artykuly/klimatyzacja/artykuly/informacje-ogolne/technika-klimatyzacyjna-i-wentylacyjna/co-to-jest-hvac-czyli-wyjasnienie-branzowego-akronimu) (*Heating, Ventilation, Air Conditioning*), którego oprogramowanie *firmware* może nie być już aktualizowane, bo np. dany producent zdążył *wypaść* z rynku i nie wydaje nowych poprawek. Wiemy jednak, że stosowane do tej pory oprogramowanie zawiera znaną lukę bezpieczeństwa. Jedną z opcji jest próba aktualizacji *firmware* na własną rękę, co może okazać się bardzo skomplikowane i zwyczajnie nieopłacalne.
 
 Inną opcją jest zastosowanie środka kompensacyjnego. W tym przypadku może być to oddzielenie panelu sterowania systemu HAVOC od sieci głównej i umieszczenie go w odizolowanej sieci [VLAN](https://pasja-informatyki.pl/sieci-komputerowe/vlan-wprowadzenie/) (*Virtual Local Area Network*). Dzięki temu ograniczymy dostęp do panelu administracyjnego, udzielając go jedynie grupie zaufanych pracowników, redukując tym samym ryzyko wykorzystania znanej podatności.
### Przykłady
- ***Technical***:
	- Zastosowanie tymczasowych reguł firewalla, blokujących dostęp do aplikacji z rażącą podatnością, do której jeszcze nie opublikowano *łatki* bezpieczeństwa (ang. *security patch*). Takie podejście może być jedyną opcją w przypadku pojawienia się luki typu [*zero-day*](https://www.kaspersky.com/resource-center/definitions/zero-day-exploit).
	- Wyodrębnienie do osobnej sieci VLAN urządzeń IoT (*Internet of Things*), posiadających stare oprogramowanie, które od dawna nie jest już rozwijane.
- ***Managerial***:
	- Kiedy nieduża firma nie posiada dedykowanego personelu ds. cyberbezpieczeństwa, więc musi porozdzielać obowiązki członkom istniejących zespołów (np. administratorom), zgodnie z ich kompetencjami.
- ***Operational***:
	- Kiedy jedna z kamer CCTV uległa uszkodzeniu i zanim zostanie wymieniona, zarządzono dodatkowy obchód pracowników ochrony w miejscu, które nie jest aktualnie monitorowane.
- ***Physical***:
	- Generator prądu, który włącza się po odcięciu głównego źródła zasilania.
## Directive
Jest to chyba *najsłabsza* forma kontroli bezpieczeństwa pod względem skuteczności, bo opiera się na tym, czy pracownicy organizacji sumiennie stosują się do przygotowanych instrukcji. 

**Głównym celem tego typu środków jest zachęcanie (a nawet wymuszanie) określonych czynności, dokładnie opisanych w ramach udokumentowanych wytycznych oraz przewodników. Są to wszelkie strategie, których zadaniem jest egzekwowanie określonych zasad i zachowań.**
### Przykłady
 - ***Technical***:
	 - Polityka bezpieczeństwa, która określa, że wszystkie wrażliwe dane przechowywane na zewnętrznych nośnikach danych muszą być zaszyfrowane.
	 - Polityka bezpieczeństwa, która mówi, że wgląd do wrażliwych danych powinien odbywać się jedynie przez wirtualne stacje robocze, dostępne w firmowej sieci VPN, z bezwzględnym zakazem ich ściągania. Jeśli nie mamy żadnego systemu DLP (*Data Loss Prevention*), który by to monitorował, to możemy polegać tylko na sumienności pracownika.
- ***Managerial***:
	- Udokumentowane polityki i procedury zgodności z obowiązującymi przepisami (*compliance*), jasno wskazujące na działania, które mają na celu uchronić pracowników przed ich naruszeniem. 
- ***Operational***:
	- Szkolenia pracowników z zakresu obowiązujących w organizacji polityk bezpieczeństwa.
- ***Physical***
	- Znak na drzwiach informujący o tym, że jest to *przejście tylko dla personelu*. Jeśli dobrze rozumiem zamysł egzaminatorów, to w odróżnieniu od znaków ostrzegawczych (*deterrent*), nie ma tutaj informacji o potencjalnych skutkach niezastosowania się do instrukcji.
# Materiały źródłowe
- [Professor Messer: Security Controls – CompTIA Security+ SY0-701](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/security-controls-sy0-701/)
- [PurpleSec: The 3 Types Of Security Controls (Expert Explains)](https://purplesec.us/security-controls/)
- [Reddit: difference between Corrective and Compensating control types](https://www.reddit.com/r/CompTIA/comments/17go8vt/studying_for_sec_struggling_to_differentiate/)
- [CompTIA Security Controls Categories and Functions](https://www.youtube.com/watch?v=WjXEd4_iB4c)