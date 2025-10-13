# 1.3 Explain the importance of change management processes and the impact to security
Wyjaśnij znaczenie procesu zarządzania zmianami oraz jego wpływ na bezpieczeństwo.
# Business processes impacting security operation
Każda zmiana, nawet najmniejsza, w rozbudowanym środowisku firmowym może nieść za sobą poważne konsekwencje dla wielu obszarów organizacji. Z tego względu **wszystkie zmiany, szczególnie w obszarze IT, powinny odbywać się w ramach sformalizowanego procesu**. Dzięki temu łatwiej jest utrzymać ciągłość działania systemów i usług, a tym samym zapewnić ciągłość działalności operacyjnej przedsiębiorstwa.

**Proces zarządzania zmianami (ang. *change management*) określa między innymi częstotliwość wprowadzania aktualizacji, dopuszczalne typy zmian wraz z harmonogramem ich wdrażania oraz plan przywrócenia poprzedniej wersji w razie poważnych problemów.**

Bez odpowiednio przemyślanego i udokumentowanego procesu zarządzania zmianami, moglibyśmy doprowadzić do poważnych problemów, które negatywnie wpływają na procesy biznesowe. Wyobraźmy sobie sytuację, że różne osoby z działu IT, bez porozumienia między sobą, wprowadzają własne modyfikacje, które są niekompatybilne.

Niemalże każda organizacja dąży do równowagi pomiędzy bezpieczeństwem i użytecznością. Sformalizowany proces zarządzania zmianą okazuje się bardzo pomocnym narzędziem w drodze do osiągnięcia tej równowagi, ponieważ zmusza osoby decyzyjne do przemyślenia i oszacowania ewentualnych konsekwencji.
## Approval process
**Każda zmiana powinna zostać formalnie zatwierdzona przez odpowiedni podmiot decyzyjny.** Pierwszym krokiem w procesie wdrażania zmian jest przygotowanie formalnego zgłoszenia (zapotrzebowania) na określoną aktualizację. Taki dokument (zazwyczaj w formie elektronicznej) powinien zawierać m.in. opis modyfikacji, jej cel, zakres oraz potencjalne skutki - w tym zagrożenia - a także planowany czas implementacji. Są to informacje niezbędne dla zespołu decyzyjnego, który ocenia, czy daną modyfikację można bezpiecznie wdrożyć.

**Rada ds. zarządzania zmianą** (ang. *Change Control Board* lub *Change Advisory Board*) - dysponując wszystkimi niezbędnymi danymi - może oszacować ryzyko związane z wdrożeniem zmiany w określonym czasie i zestawić je z ryzykiem jej niewprowadzenia.

Oczywiście, coś za coś: mając rozbudowany i sformalizowany proces zatwierdzania zmian, zmniejszamy liczbę pomyłek oraz ryzyko niepożądanych skutków, ale z drugiej strony, czas od zgłoszenia potrzeby modyfikacji do jej wdrożenia może się wydłużyć. Należy więc odpowiednio ocenić, co w danym momencie jest ważniejsze dla organizacji.

W bardzo skrajnych przypadkach, gdy administrator jest zmuszony do natychmiastowego wprowadzenia zmiany (np. w środku nocy), aby przywrócić działanie krytycznych usług, oczekiwanie na formalną decyzję może nie być wskazane. W takim przypadku zmiana powinna zostać odpowiednio udokumentowana i przejść cały proces akceptacji *ex post* (po fakcie).
## Ownership
Proces wprowadzania zmian przeważnie zaczyna się od tzw. **właściciela zasobu** (ang. *asset owner*) lub **właściciela produktu** (ang. *product owner*). Chodzi tutaj o **osobę zarządzającą danym zasobem lub produktem**, którym może być aplikacja, system, a nawet zbiór danych.

Właściciel inicjuje zmiany, ale sam ich nie wdraża. Może jednak do pewnego stopnia zarządzać całym procesem. Przykładowo, _owner_ powinien być informowany o przebiegu wdrażania oraz o ewentualnych problemach. Po zakończeniu procesu jest odpowiedzialny za weryfikację poprawnego działania podlegających mu zasobów.

Właścicielem nie musi być jedna osoba - może to być zespół, a nawet cały dział organizacji. Krótko mówiąc, są to osoby z tzw. _biznesu_, które zlecają wprowadzenie zmian zespołom IT.
## Stakeholders
**Interesariusze (ang. *stakeholders*) to wszystkie podmioty - osoby, działy lub organizacje - których dana zmiana dotyczy**. Dlatego również oni powinni zostać poinformowani o planowanych pracach oraz ich ewentualnych konsekwencjach.

Identyfikacja wszystkich interesariuszy może być sporym wyzwaniem, ponieważ nie zawsze jest oczywista. Na przykład prosta aktualizacja bazy danych, polegająca na zmianie nazwy kolumny, może wpływać nie tylko na korzystające z niej aplikacje i ich użytkowników. Może się bowiem okazać, że dział analiz generuje raporty na podstawie bezpośrednich zapytań do wspomnianej bazy - z pominięciem aplikacji. Jeśli analitycy nie zostaną poinformowani o zmianie nazwy istotnej kolumny, ich zapytania SQL generujące raporty przestaną działać.

Po wdrożeniu zmiany często prosi się użytkowników, których ta zmiana *dotknęła*, o weryfikację, czy wszystko nadal działa poprawnie.
## Impact analysis
**Analiza skutków (ang. *impact analysis*) polega na oszacowaniu potencjalnych konsekwencji wdrożenia (bądź niewdrożenia) określonej zmiany.** Każda zmiana może mieć różne skutki dla organizacji, dlatego zawsze należy ocenić potencjalne ryzyko jej zastosowania - wysokie, średnie lub minimalne.

Ryzykiem może być również sytuacja, w której aktualizacja lub poprawka niczego nie zepsuła, ale także nie spełniła swojej roli (np. wprowadzono poprawkę błędu w kodzie, ale nieskutecznie, i problem nadal występuje). Należy także uwzględnić ryzyko **niezaaplikowania** pożądanej zmiany. Na przykład brak aktualizacji oprogramowania może doprowadzić do sytuacji, w której krytyczna podatność nie zostanie usunięta, co zwiększa ryzyko udanego ataku.
## Test results
Przed wdrożeniem zmian w środowisku produkcyjnym **warto najpierw przeprowadzić stosowne testy w odizolowanym środowisku testowym**, które czasami nazywane jest _piaskownicą_ (ang. *sandbox*).

Nawet jeśli testy zakończą się pomyślnie, czasami warto **wprowadzać duże zmiany stopniowo**. Na przykład aktualizacja środowiska produkcyjnego może na początku objąć tylko jedną, najmniej krytyczną usługę. Jeśli stwierdzimy, że wszystko działa prawidłowo, możemy rozszerzyć aktualizację na kolejne, ważniejsze usługi.

Środowisko testowe powinno być możliwie jak najbardziej zbliżone do środowiska produkcyjnego, aby uniknąć problemów wynikających z rozbieżnej konfiguracji i nie przeoczyć potencjalnych błędów w przyszłości.
## Backout plan
Nawet jeśli testy przebiegły pomyślnie, **bardzo istotne jest przygotowanie szczegółowej procedury wycofania zmiany, która powinna być przetestowana i dobrze udokumentowana**. Docenimy to szczególnie podczas nocnych wdrożeń - gdy o 3 nad ranem coś pójdzie nie tak i okaże się, że jedynym wyjściem jest przywrócenie pierwotnego stanu.

Niektóre zmiany mogą być proste do wycofania (np. przywrócenie poprzedniej wersji aplikacji jednym kliknięciem, jeśli mamy prawidłowo skonfigurowane pipeline'y CI/CD), ale są też takie, których cofnięcie wymaga większego wysiłku (np. gdy podczas migracji danych wystąpił błąd i część tabel w bazie została zaktualizowana, a część nie).

Oprócz planu awaryjnego warto mieć również pełne _backupy_ danych oraz konfiguracji. Jeśli coś pójdzie naprawdę źle, a wycofanie zmian okaże się mocno problematyczne, zawsze możemy przywrócić stan systemu, aplikacji czy bazy danych z ostatniej kopii zapasowej - dlatego tak ważne jest, by były one regularnie tworzone i możliwie aktualne.
## Maintenance window
Ważnym aspektem procesu zarządzania zmianami jest ustalenie, kiedy powinno nastąpić wdrożenie. Okazuje się, że nie zawsze jest to takie oczywiste - nie chcemy przecież zakłócić pracy organizacji, a przynajmniej nie na długo.

Jeśli zmiana wiąże się z niedostępnością określonych usług, często trzeba ją wprowadzić poza godzinami biznesowymi. Jeśli działalność opiera się na potrzebie ciągłego funkcjonowania (jak np. banki czy serwisy informacyjne), najlepiej takie operacje przeprowadzać w nocy - czyli wtedy, gdy najmniej osób korzysta z usług organizacji.

**Ustalony czas, w którym zmiana może zostać w miarę bezpiecznie wprowadzona, nazywamy *oknem serwisowym* (ang. *maintenance window*) i należy o nim poinformować wszystkich interesariuszy.**

Warto również rozważyć, czy nie jesteśmy akurat w trakcie *gorącego* okresu dla przedsiębiorstwa. Na przykład dla firm sprzedażowych takim czasem może być okres przed Bożym Narodzeniem, w którym obserwuje się duży wzrost zamówień. Dlatego też każde okno serwisowe powinno zostać wcześniej formalnie zatwierdzone przez odpowiednie jednostki organizacyjne (np. CAB = *Change Advisory Board*).
## Standard operating procedure
**Standardowa procedura operacyjna (ang. *standard operating procedure*, SOP) to dokument zawierający zbiór szczegółowych instrukcji i procedur obowiązujących w danej organizacji, który powinien być dostępny dla wszystkich zainteresowanych pracowników** (np. za pośrednictwem intranetu). Mówiąc krótko, jest to zbiór instrukcji pomagających pracownikom wykonywać swoje obowiązki.

Procedura zarządzania zmianami powinna być częścią SOP. Należy w niej zaznaczyć, że żadna zmiana nie może zostać wprowadzona bez uprzedniego uzyskania zgody (ang. *approval*) od odpowiedniego podmiotu (np. CAB).

Przykładowa zawartość dokumentu opisującego proces zarządzania zmianą może obejmować następujące punkty:
1. **Zgłoszenie potrzebnej zmiany.** Jeśli pojawia się potrzeba wdrożenia określonej modyfikacji, należy to formalnie zgłosić za pomocą systemu używanego przez organizację (np. [Jira](https://www.atlassian.com/pl/software/jira)). Oprócz informacji o tym, co należy zmienić, istotne jest również rzeczowe uzasadnienie.
2. **Przegląd i analiza zgłoszenia.** Każde żądanie zmiany powinno zostać dogłębnie przeanalizowane pod kątem potencjalnego ryzyka (*impact analysis*) i uzgodnione z wszystkimi zainteresowanymi, których dana zmiana może *dotknąć*. Analiza jest zazwyczaj przeprowadzana przez odpowiedni zespół CAB (*Change Advisory Board*), który może spotykać się regularnie (np. raz w tygodniu) lub w trybie *ad hoc*, jeśli wymaga tego sytuacja (np. poprawka krytycznej podatności, gdzie czas odgrywa istotną rolę).
3. **Zatwierdzenie bądź odrzucenie zmiany.** Zespół (możliwy także jednoosobowy) podejmuje decyzję o wdrożeniu zgłoszonej zmiany bądź jej odrzuceniu, na podstawie otrzymanych informacji oraz przeprowadzonej analizy. Decyzja wraz z jej uzasadnieniem powinna zostać odpowiednio udokumentowana. Odrzucenie nie musi być definitywne - może się zdarzyć, że żądanie zmiany wymaga uzupełnienia o dodatkowe informacje (np. procedurę przywrócenia pierwotnej wersji w razie niepowodzenia), zanim zostanie zaakceptowane.
4. **Testowanie zmiany.** Nawet jeśli żądanie wdrożenia zmiany zostało zaakceptowane, powinna istnieć możliwość przetestowania wprowadzonych modyfikacji w odizolowanym środowisku, zbliżonym do produkcyjnego. Pozwoli to zweryfikować, czy nie wystąpią nieprzewidziane wcześniej komplikacje.
5. **Zaplanowanie i wdrożenie zmiany.** Gdy modyfikacja została przetestowana i jest gotowa do wprowadzenia, należy ustalić termin jej wdrożenia (w ramach wspomnianego wcześniej *maintenance window*).
6. **Aktualizacja dokumentacji.** Każda wprowadzona zmiana powinna zostać odnotowana w dokumentacji stosowanej przez organizację, celem utrzymania jej aktualności.
# Technical implications
Omówiliśmy wcześniej procesy zarządzania zmianami z biznesowego punktu widzenia. Jednakże samo wdrożenie zmian leży w gestii zespołów technicznych, które wiedzą (a przynajmniej powinny) w jaki sposób to uczynić. W zależności od tego, co dokładnie należy zrobić, operacja może być technicznie prosta (np. niewielka aktualizacja oprogramowania na jednym z serwerów), ale może też być bardzo złożona, szczególnie jeśli dotyczy dużej liczby urządzeń i systemów działających w danej organizacji, np. zainstalowanie oprogramowania EDR (*Endpoint Detection and Response*) na wszystkich stacjach roboczych należących do firmy.

Mówiąc krótko: ***biznes* decyduje co, kiedy i dlaczego należy zmienić, ale to pracownicy techniczni przeprowadzają samą operację**.

Kwestie techniczne, które warto wziąć pod uwagę podczas analizy zgłoszenia zmiany:
- Jakie zmiany konfiguracyjne należy wprowadzić w stosowanych środkach bezpieczeństwa (np. w ustawieniach firewalla)?
- Czy podczas wdrożenia należy ograniczyć działanie bądź całkowicie wyłączyć określone usługi, aplikacje lub zaprzestać wybranych działań pracowników?
- Czy wdrożenie wiąże się z niedostępnością wybranych usług?
- Czy wdrożenie będzie wymagało ponownego uruchomienia aplikacji, usług bądź całych systemów?
- Czy zmiana dotyczy starych aplikacji, które nie są już rozwijane?
- Czy w zgłoszeniu wprowadzenia zmiany uwzględniono wszystkie zależności?
## Allow lists/deny lists 
Jedną z częstych operacji jest przydzielanie bądź odbieranie dostępu lub uprawnień wybranym aplikacjom, usługom czy też użytkownikom. W tym celu wykorzystuje się **listy dostępu** (ang. *allow lists*) i/lub **listy blokujące** (ang. *black lists*, *deny lists*, *block lists*). 

Listy są ogólnym konceptem, którego implementacja zależy od tego, co dokładnie konfigurujemy. Inaczej działają listy na poziomie firewalla, a jeszcze inaczej listy uprawnień użytkowników systemu operacyjnego, ale ogólna idea jest taka sama:
- ***Allow list*** - jak sama nazwa wskazuje, **wszystko, co znajduje się na tej liście, jest dozwolone** (np. tylko aplikacje znajdujące się na danej liście mogą zostać uruchomione w danym systemie). Wykorzystanie tzw. *białej listy* jest teoretycznie najbezpieczniejszym, ale również najbardziej restrykcyjnym podejściem, ponieważ **jeśli czegoś nie ma na tej liście, jest w domyśle zablokowane lub niedozwolone**.
- ***Deny list*** - nazywana również *czarną listą* (tutaj warto zaznaczyć, że ten termin figuruje w Wikipedii, ale osobiście rzadko spotykam się z jego praktycznym użyciem). **Wszystko, co znajduje się na tej liście, jest z kolei zablokowane bądź niedozwolone**. W tym przypadku mamy do czynienia z luźniejszym podejściem, ponieważ **w domyśle wszystko, co nie jest zabronione, jest dozwolone**. Tę praktykę często stosuje się w oprogramowaniu typu *anti-malware* - jeśli program nie wygląda podejrzanie (tj. nie znaleziono odpowiednich sygnatur w bazie danych), to może zostać uruchomiony.
## Restricted activities
**Zakres wszystkich planowanych zmian powinien zostać udokumentowany oraz zatwierdzony przez radę ds. zarządzania zmianą (*change control board*) i zespół odpowiedzialny za wdrożenie powinien się tego trzymać**. Na przykład, jeśli celem jest jedynie aktualizacja aplikacji klienckich firmowego systemu fakturowego, to w ramach zaplanowanych prac nie powinniśmy dodatkowo instalować poprawek systemu operacyjnego, jeśli te nie są wymagane do realizacji planu.

W wyjątkowych sytuacjach, kiedy osiągnięcie celu wdrożenia wymaga dodatkowych czynności, które nie zostały przewidziane przed zgłoszeniem planowanych zmian do akceptacji, zespół może wprowadzić dodatkowe, niezbędne modyfikacje. 

Jednakże jest to zależne od aktualnie obowiązującej polityki oraz złożoności nadplanowych zmian, które mogą być na tyle poważne, że czasami rozsądniej jest anulować bieżący proces wdrażania i zaplanować nowy. **Procedury postępowania w takich sytuacjach również powinny zostać prawidłowo udokumentowane.**
## Downtime
**Może się zdarzyć, że wdrażanie zmian, szczególnie tych poważniejszych, wiąże się z tymczasową niedostępnością działania (ang. *downtime*) sieci, systemów, usług bądź aplikacji**. Właśnie z tego względu ustala się wcześniej okna serwisowe (ang. *maintenance windows*) w okresach, kiedy przerwy w działaniu będą najmniej uciążliwe dla wszystkich zainteresowanych.

W środowiskach wymagających wysokiej dostępności (ang. *high availability*), w których usługi powinny być dostępne przez 24 godziny na dobę, przez 7 dni w tygodniu, jest to szczególne wyzwanie. W takim przypadku stosuje się **podejście *zero downtime*, czyli wszelkiego rodzaju techniki umożliwiające wdrażanie zmian bez jakichkolwiek przerw w dostępie do usług.** 

Przykładem może być posiadanie dwóch instancji tej samej usługi, pomiędzy którymi można się szybko przełączyć. Najpierw modyfikujemy jedną instancję, a w tym czasie użytkownicy cały czas korzystają z drugiej instancji. Kiedy proces wdrożenia się skończy i upewnimy się, że wszystko działa jak należy, przekierowujemy ruch na zaktualizowaną kopię. Teraz możemy bezpiecznie i w spokoju wprowadzić niezbędne zmiany w pozostałych instancjach.

Czasami okres niedostępności może nastąpić przez przypadek, wskutek nieprzewidzianych komplikacji podczas procesu wdrażania zmian. Zawsze należy brać pod uwagę ryzyko wystąpienia takiego scenariusza już na etapie planowania, zanim zapadnie decyzja o akceptacji.

**Niezależnie od tego, czy przerwy w dostępie są planowane, czy ryzyko ich wystąpienia jest minimalne, wszyscy interesariusze (ang. *stakeholders*) powinni zostać o tym wcześniej powiadomieni za pośrednictwem oficjalnych kanałów komunikacyjnych.**
## Service restart
**Często, po wdrożeniu zmian, wymagane jest ponowne uruchomienie usługi (ang. *service*), aby modyfikacje przyniosły oczekiwany efekt**. W skrajnych przypadkach może być konieczny restart całego systemu operacyjnego (ang. *reboot*), a tym samym – wszystkich działających na nim usług.

Usługi są specjalnymi aplikacjami działającymi w tle, bez widocznego interfejsu użytkownika. W systemach Linux takie aplikacje nazywane są również *demonami* (ang. *daemon*).

Proces ponownego uruchomienia usługi lub demona może trwać od kilku sekund do kilku minut, w zależności od operacji wykonywanych podczas startu danej usługi bądź wymaganych zależności (np. do uruchomienia jednej usługi wymagane jest działanie innej).

Ponowne uruchomienie usług pozwala również zweryfikować, czy proces ich startu przebiega poprawnie po wprowadzeniu najnowszych zmian. Dzięki temu upewnimy się, że po niespodziewanym restarcie całego serwera system wraz z usługami wróci do pożądanego stanu.
## Application restart
Oprócz wspomnianych wyżej usług działających w tle, zmiany mogą zostać wprowadzone w zwyczajnych aplikacjach (webowych, desktopowych, mobilnych), z których na co dzień korzystają użytkownicy.

**Aktualizacja kodu aplikacji również może wymagać jej ponownego uruchomienia** – w takim przypadku użytkownicy korzystający z aplikacji zostaną automatycznie wylogowani i będą zmuszeni do ponownego zalogowania się. W związku z tym konieczne jest zadbanie o to, żeby wszyscy użytkownicy byli świadomi odbywających się prac serwisowych i mogli wcześniej zapisać efekty swojej pracy.
## Legacy applications
Termin *legacy*, w dosłownym tłumaczeniu, oznacza *dziedzictwo, spuściznę, spadek*. ***Legacy application* oznacza starą aplikację, która nie jest już w żaden sposób rozwijana, ale dalej spełnia swoje zadanie, a zastąpienie jej nową technologią jest często nieopłacalne**. Przymiotnikiem *legacy* można określić również system złożony z wielu aplikacji, który jest już tylko utrzymywany.

Zdarza się, że w organizacji nie ma już nawet osób, które pracowały nad takimi aplikacjami. Częstą przypadłością jest też brak dokumentacji technicznej, więc utrzymanie starych rozwiązań sprowadza się do podejścia: *jak działa, to nie ruszamy*.

Mimo wszystko przychodzi taki moment, że jednak trzeba wprowadzić pewne modyfikacje i aktualizacje, żeby aplikacja mogła dalej działać. W takim przypadku, jeśli w organizacji nie ma już osób z odpowiednią wiedzą, najrozsądniejszym wyjściem powinno być poznanie niuansów starego rozwiązania (mówiąc wprost: nauczenie się, jak działa) oraz przygotowanie solidnej dokumentacji, aby nie powtórzyła się sytuacja, w której z firmy odchodzi ostatni wtajemniczony deweloper.

Należy pamiętać, że w przypadku starych rozwiązań, które nie spełniają standardów aktualnie obowiązujących w organizacji (np. aplikacja została stworzona w nieużywanej już technologii), może być konieczne wypracowanie nowych, dedykowanych procedur zarządzania zmianami.
## Dependencies
**W przypadku złożonych systemów niejednokrotnie natkniemy się na zależności (ang. *dependencies*), które powodują, że trudno jest aktualizować lub modyfikować poszczególne komponenty niezależnie**. Może to znacznie utrudnić proces zarządzania zmianą, jak i samo wdrożenie – **trzeba bowiem wziąć pod uwagę konieczność wprowadzenia zmian w kilku miejscach i to w odpowiedniej kolejności.**

Weźmy pod uwagę przykładowy scenariusz, który zdarza się dosyć często w praktyce: w aktualnie wykorzystywanej przez nas wersji biblioteki programistycznej wykryto poważną lukę bezpieczeństwa. Trzeba więc jak najszybciej *podbić* wersję biblioteki we wszystkich aplikacjach i usługach działających w organizacji. Niestety, okazało się, że najnowsza wersja nie współpracuje już z wersją języka programowania zainstalowaną obecnie na serwerach organizacji. Jakby tego było mało, żeby zaktualizować wersję języka programowania, konieczna jest aktualizacja systemu operacyjnego.

Jak widać, pozornie niewielka zmiana (aktualizacja biblioteki), ze względu na istniejące zależności, spowodowała, że musimy wziąć pod uwagę wiele różnych aspektów podczas wdrożenia aktualizacji.

Nieocenioną pomocą przy identyfikowaniu zależności jest posiadanie tzw. listy SBOM (_Software Bill of Materials_), czyli cyfrowego _spisu treści_ oprogramowania, zawierającego dokładne informacje o wszystkich komponentach, bibliotekach i ich wersjach.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
