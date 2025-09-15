# 4.1 Given a scenario, apply common security techniques to computing resources
Na podstawie podanego scenariusza, zastosuj odpowiednie techniki zabezpieczające dla wybranych zasobów.
# Secure baselines
Kiedy wdrażamy w naszej organizacji nową aplikację bądź system składający się z wielu komponentów, oprócz niezawodności działania, powinniśmy brać również pod uwagę aspekty bezpieczeństwa. Jeśli produkty są dostarczone przez zaufanych dostawców, to istnieje wysokie prawdopodobieństwo, że zostały już zaprojektowane i zaimplementowane w sposób zapewniający bezpieczeństwo ich użytkowania.

Niestety, czasami może to być za mało i osoby odpowiedzialne za wdrażanie nowych rozwiązań w organizacji, powinny uwzględnić specyfikę środowiska, w których te rozwiązania będą funkcjonować. Oprócz ustawień samych aplikacji, często należy również dostosować ustawienia systemu operacyjnego, konfigurację firewalla, politykę instalowania aktualizacji itd.

Oznacza to, że **aby wdrożyć i użytkować nową aplikację lub system w sposób bezpieczny, należy postępować zgodnie z ustalonymi wcześniej, podstawowymi wytycznymi dotyczącymi bezpieczeństwa (*secure/security baseline*)**. Jest to przeważnie **dokument w postaci przewodnika lub listy kontrolnej (ang. *checklist*), zawierający informację o sposobie konfiguracji samego rozwiązania oraz środowiska w taki sposób, żeby zapewnić akceptowalny poziom bezpieczeństwa, dostosowany do potrzeb organizacji**.
## Establish
**Pierwszym krokiem jest ustalenie i zebranie wszystkich istotnych zaleceń dotyczących bezpieczeństwa, które posłużą jako nasz punkty wyjściowy (ang. *baseline*)**. Przygotowanie takich wytycznych od zera, bez dogłębnego zrozumienia wdrażanej aplikacji bądź systemu, jest zadaniem bardzo trudnym. Dlatego **dostawcy rozwiązań (ang. *vendors*) bardzo często sami opracowują i udostępniają (np. w oficjalnej dokumentacji) wszystkie niezbędne wytyczne, z których możemy skorzystać**.

*Secure baselines* można wypełnić co do joty bądź skorzystać tylko z tych elementów, które są dla nas istotne i odpowiednio je dostosować. Możliwa jest sytuacja, w której różne zestawy wytycznych nachodzą na siebie (np. kiedy wdrażamy kilka różnych rozwiązań) i niektóre ich pozycje wzajemnie się wykluczają. W takim przypadku musimy świadomie wybrać to, co będzie najlepiej dostosowane do potrzeb organizacji.
## Deploy
Kiedy zebraliśmy już wszystkie istotne dla nas wytyczne, możemy przystąpić do ich wdrażania (ang. *deploy*). **Proces ten polega na dokładnym sprawdzeniu konfiguracji (rozwiązania i środowiska) oraz dostosowaniu ustawień w taki sposób, żeby zgadzały się z przygotowaną wcześniej listą wytycznych**.

Podczas procesu wdrażania, **zawsze powinniśmy automatyzować co tylko się da**, szczególnie kiedy musimy skonfigurować wiele urządzeń w organizacji (np. nowa aplikacja jest instalowana na maszynach roboczych wielu pracowników i na każdej z nich trzeba dostroić ustawienia). W związku z tym, powinniśmy korzystać z odpowiednich narzędzi, takich jak skrypty automatyzujące czy systemy centralnego zarządzania (np. [*Group Policy* w systemach Windows](https://sekurak.pl/notatnik-ze-szkolenia-poznaj-bezpieczenstwo-windows-3-tajniki-group-policy/)).

Istotna uwaga: **kiedy wdrażamy *security baselines*, nie powinniśmy ich aplikować od razu w środowisku produkcyjnym**. Najbezpieczniej byłoby upewnić się, że nowa konfiguracja działa tak jak tego oczekujemy, stosując ją najpierw w środowisku testowym.
## Maintain
Kiedy wszystkie (istotne dla naszej organizacji) wytyczne dotyczące bezpieczeństwa zostały już wdrożone i działają jaka należy, musimy jeszcze pamiętać o ich utrzymywaniu (ang. *maintain*).

**Utrzymywanie polega na regularnym sprawdzaniu, czy aktualne ustawienia aplikacji/systemu w dalszym ciągu są zgodne z podstawowymi wytycznymi oraz wprowadzaniu ewentualnych poprawek, jeśli coś się *rozjeżdża***. Dobrym pomysłem jest zastosowanie procesu monitorowania, który także jest maksymalnie zautomatyzowany (w miarę możliwości).

Niezgodność wynika przeważnie z nieprzewidzianych bądź nieprzemyślanych zmian w konfiguracji po naszej stronie (często stosowanych *ad hoc*), ponieważ same wytyczne zmieniają się raczej rzadko. Powodem aktualizacji wytycznych może być wykrycie nowej podatności związanej z używanym przez nas rozwiązaniem i/lub środowiskiem czy też zwyczajny *upgrade* oprogramowania (aplikacji, systemu operacyjnego) do nowszej wersji.
## Przykłady
### Microsoft Windows
Pierwszym z brzegu przykładem dostawcy, który udostępnia szczegółowe wytyczne jest Microsoft. W oficjalnej dokumentacji [Security baselinses](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) znajdziemy ogólne informacje o znaczeniu podstawowych wytycznych bezpieczeństwa w systemach Windows oraz o narzędziach, które umożliwią ich wdrożenie i utrzymanie.

Krótkie podsumowanie wspomnianej dokumentacji:
- System Windows 10 ma ponad 3000 [polityk grupowych GPO](https://kapitanhack.pl/2022/04/07/nieskategoryzowane/zasady-grupy-gpo-i-ich-rola-w-bezpieczenstwie-danych/), nie wliczając w to osobnych ustawień dla Internet Explorer 11, ale tylko niektóre z nich dotyczą bezpieczeństwa.
- Microsoft zaleca, żeby trzymać się konfiguracji, która została opracowana na podstawie szeroko stosowanych standardów.
- Wytyczne zostały zaprojektowane z myślą o dobrze zarządzanych środowiskach (m.in. pod kątem bezpieczeństwa), w których zwykli użytkownicy nie posiadają uprawnień administracyjnych.
- Opracowane wytyczne wymuszają wartość konkretnego ustawienia tylko wtedy, gdy mityguje to potencjalne zagrożenie i jednocześnie nie powoduje problemów operacyjnych, poważniejszych niż skutek samego zagrożenia (w niektórych sytuacjach ryzyko jest akceptowalne).
- Wytyczne wymuszają domyślne ustawienie określonej polityki (polityka GPO może mieć 3 stany: włączona/wyłączona/nie ustawiona) tylko wtedy, gdy dozwolona wartość wybrana przez zwykłego użytkownika bądź administratora może być potencjalnie niebezpieczna.
- Microsoft udostępnia zestaw narzędzi automatyzujących wdrożenie zalecanych polityk bezpieczeństwa: [Security Compliance Toolkit (SCT)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10). Rozwiązanie zawiera wytyczne dla różnych systemów z rodziny Windows oraz narzędzia do ich aplikowania.
### CIS Benchmarks List
Firma *Center for Internet Security* (CIS) udostępnia listę rekomendowanych konfiguracji bezpieczeństwa dla różnych produktów, pochodzących od różnych dostawców: https://www.cisecurity.org/cis-benchmarks. Warto tutaj zwrócić uwagę, że udostępnione za darmo dokumenty powinny służyć jedynie do niekomercyjnych zastosowań.
### SANS - Security Policy Templates
Jeśli nie byliśmy w stanie znaleźć gotowych *secure baselines* dla instalowanych przez nas rozwiązań, musimy stworzyć je sami. W takim przypadku warto wykorzystać gotowe szablony, które posłużą nam jako punkt wyjścia.

Instytut [SANS](https://www.sans.org/emea/) udostępnia zbiór szablonów, na podstawie których można opracować polityki bezpieczeństwa dostosowane do naszych potrzeb (z różnych obszarów): https://www.sans.org/information-security-policy/.
# Materiały źródłowe
- [Professor Messer’s CompTIA SY0-701 Security+ Training Course](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/)
- [CompTIA Security+ Study Guide SY0-701, Mike Chapple, David Seidl](https://www.amazon.com/CompTIA-Security-Study-Practice-Questions/dp/1394211414)
- [Windows: Security baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [O-Line Security: Understanding Security Baselines](https://www.youtube.com/watch?v=FYLGAJhmKY0)