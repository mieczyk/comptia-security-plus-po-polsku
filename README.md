# CompTIA Security+ SY0-701 po polsku (dosłownie i w przenośni)
Celem tego projektu jest przygotowanie polskojęzycznego kompendium z opracowaniami [zagadnień obowiązujących na egzaminie CompTIA Security+ SY0-701](https://github.com/mieczyk/comptia-security-plus-po-polsku/blob/main/SY0-701-Exam-Objectives.pdf). 

Ponieważ sam egzamin jest skierowany głównie do osób, które chcą wejść do branży cyberbezpieczeństwa (*entry level*), staram się, żeby wszystkie zagadnienia były opisane w sposób przystępny i zrozumiały, nawet dla tych, którzy nie mieli wcześniej styczności z szeroko pojętym IT.
# Dlaczego powstał ten projekt?
Wielu może się zastanawiać, po co w ogóle tworzyć taki zbiór, skoro w sieci można znaleźć mnóstwo materiałów potrzebnych do zdania egzaminu, na czele z niezastąpionym [Professorem Messerem](https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/). Poza tym może zrodzić się pytanie: dlaczego opracowania są w języku polskim, skoro sam egzamin jest po angielsku?

Na te i inne pytania postaram się odpowiedzieć w punktach:
- Kiedy sam [przygotowywałem się do egzaminu](https://vilya.pl/wrazenia-z-egzaminu-comptia-security-sy0-601-online/), przerabiając kurs wideo Professora Messera, brakowało mi trochę **tekstowego opracowania poszczególnych zagadnień, które byłyby dostępne w jednym miejscu**. Kiedy chciałbym przypomnieć sobie jakieś konkretnie zagadnienie z listy, od razu widziałbym jego opis. Wynika to z tego, że osobiście preferuję słowo pisane.
- Pomimo tego, że Professor Messer oraz książki przygotowujące do egzaminu są świetnym źródłem wiedzy, to jednak brakowało mi czasami bardziej szczegółowych opisów niektórych zagadnień, które niekiedy wymagają głębszego zrozumienia. Zdać egzamin to jedno, ale zrozumieć dany temat, to zupełnie inna kwestia.
- Przygotowywanie swoich notatek i publikowanie ich w postaci artykułów na [blogu](https://vilya.pl/tag/comptia/) sprawiło, że byłem w stanie **dogłębniej zrozumieć omawiane zagadnienia**, które również dzięki temu **zostały na dłużej w pamięci** (zgodnie z [techniką Feynmana](https://pl.wikipedia.org/wiki/Technika_Feynmana)). Doszedłem jednak do wniosku, że w pojedynkę nie dam rady opisać wszystkich zagadnień z aktualnej edycji (SY0-701) w rozsądnym czasie (chyba, że zamknąłbym się w piwnicy na cały rok). Stąd pomysł na udostępnienie moich dotychczasowych materiałów w ramach projektu open source, do którego każda chętna osoba będzie mogła dołożyć swoją *cegiełkę*.
- Dlaczego po polsku, a nie po angielsku? Mikołaj Rej kiedyś napisał: *A niechaj narodowie wżdy postronni znają, iż Polacy nie gęsi, iż swój język mają.* Przyznaję, że jest to moja **osobista preferencja**. Zapoznanie się z materiałem w języki angielskim i opisanie danego tematu w języku polskim sprawia, że **zapamiętuję go na dłużej**. Poza tym przypuszczam, że wśród odbiorców mogą być osoby początkujące, które jeszcze nie są zaznajomione z językiem angielskim na tyle, żeby bezproblemowo zrozumieć powszechnie dostępne materiały. Oczywiście prędzej czy później angielski staje się niezbędny do pracy w cyberbezpieczeństwie (i ogólnie w IT), ale liczę, że **dzięki polskim opracowaniom uda się choć trochę obniżyć próg wejścia dla odpowiednio zdeterminowanych**.
- Ostatni powód jest bardzo osobisty: **chcę skończyć to, co już zacząłem**.  
# Jak długo projekt będzie realizowany?
Planuję rozwijać ten projekt **do momentu, aż wszystkie zagadnienia z edycji SY0-701 zostaną opisane lub do daty premiery nowej edycji egzaminu CompTIA Security+ SY0-801**. Czasu zostało niewiele (prawdopodobnie rok), więc nie ukrywam, że liczę również na Waszą pomoc.
# Spis treści
## 1.0 General Security Concepts
### 1.1 Compare and contrast various types of security controls
- [Categories](1-general-security-concepts/1-1-security-controls.md#categories)
	- [Technical](1-general-security-concepts/1-1-security-controls.md#technical)
	- [Managerial](1-general-security-concepts/1-1-security-controls.md#managerial)
	- [Operational](1-general-security-concepts/1-1-security-controls.md#operational)
	- [Physical](1-general-security-concepts/1-1-security-controls.md#physical)
- [Control types](1-general-security-concepts/1-1-security-controls.md#control-types)
	- [Preventive](1-general-security-concepts/1-1-security-controls.md#preventive)
	- [Detective](1-general-security-concepts/1-1-security-controls.md#detective)
	- [Corrective](1-general-security-concepts/1-1-security-controls.md#corrective)
	- [Compensating](1-general-security-concepts/1-1-security-controls.md#compensating)
	- [Directive](1-general-security-concepts/1-1-security-controls.md#directive)
### 1.2 Summarize fundamental security concepts
- [Confidentiality, Integrity, and Availability (CIA)](1-general-security-concepts/1-2-fundamental-security-concepts.md#confidentiality-integrity-and-availability-cia)
	- [Confidentiality](1-general-security-concepts/1-2-fundamental-security-concepts.md#confidentiality)
	- [Integrity](1-general-security-concepts/1-2-fundamental-security-concepts.md#integrity)
	- [Availability](1-general-security-concepts/1-2-fundamental-security-concepts.md#availability)
- [Non-repudiation](1-general-security-concepts/1-2-fundamental-security-concepts.md#non-repudiation)
- [Authentication, Authorization, and Accounting (AAA)](1-general-security-concepts/1-2-fundamental-security-concepts.md#authentication-authorization-and-accounting-aaa)
	- [Authenticating people](1-general-security-concepts/1-2-fundamental-security-concepts.md#authenticating-people)
	- [Authenticating systems](1-general-security-concepts/1-2-fundamental-security-concepts.md#authenticating-systems)
	- [Authorization models](1-general-security-concepts/1-2-fundamental-security-concepts.md#authorization-models)
- [Gap analysis](1-general-security-concepts/1-2-fundamental-security-concepts.md#gap-analysis)
- [Zero Trust](1-general-security-concepts/1-2-fundamental-security-concepts.md#zero-trust)
	- [Control Plane](1-general-security-concepts/1-2-fundamental-security-concepts.md#control-plane)
		- [Adaptive identity](1-general-security-concepts/1-2-fundamental-security-concepts.md#adaptive-identity)
		- [Threat scope reduction](1-general-security-concepts/1-2-fundamental-security-concepts.md#threat-scope-reduction)
		- [Policy-driven access control](1-general-security-concepts/1-2-fundamental-security-concepts.md#policy-driven-access-control)
		- [Policy Administrator](1-general-security-concepts/1-2-fundamental-security-concepts.md#policy-administrator)
		- [Policy Engine](1-general-security-concepts/1-2-fundamental-security-concepts.md#policy-engine)
	- [Data Plane](1-general-security-concepts/1-2-fundamental-security-concepts.md#data-plane)
		- [Implicit trust zones](1-general-security-concepts/1-2-fundamental-security-concepts.md#implicit-trust-zones)
		- [Subject/System](1-general-security-concepts/1-2-fundamental-security-concepts.md#subjectsystem)
		- [Policy Enforcement Point](1-general-security-concepts/1-2-fundamental-security-concepts.md#policy-enforcement-point)
### 1.3 Explain the importance of change management processes and the impact to security
- [Business processes impacting security operation](1-general-security-concepts/1-3-change-management-processes.md#business-processes-impacting-security-operation)
	- [Approval process](1-general-security-concepts/1-3-change-management-processes.md#approval-process)
	- [Ownership](1-general-security-concepts/1-3-change-management-processes.md#ownership)
	- [Stakeholders](1-general-security-concepts/1-3-change-management-processes.md#stakeholders)
	- [Impact analysis](1-general-security-concepts/1-3-change-management-processes.md#impact-analysis)
	- [Test results](1-general-security-concepts/1-3-change-management-processes.md#test-results)
	- [Backout plan](1-general-security-concepts/1-3-change-management-processes.md#backout-plan)
	- [Maintenance window](1-general-security-concepts/1-3-change-management-processes.md#maintenance-window)
	- [Standard operating procedure](1-general-security-concepts/1-3-change-management-processes.md#standard-operating-procedure)
- [Technical implications](1-general-security-concepts/1-3-change-management-processes.md#technical-implications)
	- [Allow lists/deny lists](1-general-security-concepts/1-3-change-management-processes.md#allow-listsdeny-lists)
	- [Restricted activities](1-general-security-concepts/1-3-change-management-processes.md#restricted-activities)
	- [Downtime](1-general-security-concepts/1-3-change-management-processes.md#downtime)
	- [Service restart](1-general-security-concepts/1-3-change-management-processes.md#service-restart)
	- [Application restart](1-general-security-concepts/1-3-change-management-processes.md#application-restart)
	- [Legacy applications](1-general-security-concepts/1-3-change-management-processes.md#legacy-applications)
	- [Dependencies](1-general-security-concepts/1-3-change-management-processes.md#dependencies)
### 1.4 Explain the importance of using appropriate cryptographic solutions
- [Public key infrastructure (PKI)](1-general-security-concepts/1-4-cryptographic-solutions.md#public-key-infrastructure-pki)
	- [Public key](1-general-security-concepts/1-4-cryptographic-solutions.md#public-key)
	- [Private key](1-general-security-concepts/1-4-cryptographic-solutions.md#private-key)
	- [Key escrow](1-general-security-concepts/1-4-cryptographic-solutions.md#key-escrow)
- [Hashing](1-general-security-concepts/1-4-cryptographic-solutions.md#hashing)
- [Salting](1-general-security-concepts/1-4-cryptographic-solutions.md#salting)
- [Digital signatures](1-general-security-concepts/1-4-cryptographic-solutions.md#digital-signatures)
- [Key stretching](1-general-security-concepts/1-4-cryptographic-solutions.md#key-stretching)
## 4.0 Security Operations
### 4.1 Given a scenario, apply common security techniques to computing resources
- [Secure baselines](4-security-operations/4-1-common-security-techniques.md#secure-baselines)
	- [Establish](4-security-operations/4-1-common-security-techniques.md#establish)
	- [Deploy](4-security-operations/4-1-common-security-techniques.md#deploy)
	- [Maintain](4-security-operations/4-1-common-security-techniques.md#maintain)