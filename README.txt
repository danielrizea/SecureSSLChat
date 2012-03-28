Rizea Daniel-Octavian
341C1


				Tema 4 SPRC


	Clase:
		-Client : clasa specifica clientul 
		-Server : clasa ce specifica serverul (simuleaza existenta a 4 servere : management, it,hr,accounting)
		-AuthorizationService : clasa ce ruleaza serviciul de autorizare (management prioritati de access si banned users)
		-EasyX509TrustManager : clasa ce implementeaza trust manager cu autentificare bidirectionala (accepta numai certificate semnate de MyCompany, in certificat campul issuer O: == MyCompany )


	Compilare :
		sunt deja create keystorurile si truststorurile necesare pentru rulare.
		acestea pot fi recreate cu comenzile :
			- ant ca : creeaza certificat cu care se vor semna celelalte
			- ant keystore : foloseste certificatul creat la pasul precedent pentru a semna certificatele urmatoare

	Rulare:
		se porneste mai intain serviciul de autorizare 
				ant authorizationService
		se porneste serverul (va emula toate departamentele)
				ant server
			
		se pornesc clientii : ant client1, ant client2, ant client3

		despre certificate:
		
		client1 CN:User1 OU:HR
		client2 CN:User2 OU:IT
		client3 CN:User3 Ou:Accounting

		foarte important , deoarece se emuleaza cele 4 servere (it, management, hr,accounting), trebuie dupa ce s-a efectuat cu succes handshack-ul
utilizatorul sa isi manifeste dorinta de conexiune la un server, comanda ex: connect it/hr/management/accounting(totul in baza permisiunilor sale). Se poate conecta la mai multe servere si va primi mesaje de la fiecare.
Daca utilizatorul scrie cuvantul bamba spre exemplu, serverul il va semnala serviciului de autorizare care il va marca ca fiind in ban, va scrie intrarea lui intr-un mod criptat in fisierul banned_list.Daca serviciul de autorizare se intrerupe brusc(ctrl+C) si se reporneste, acesta va fi reincarcat cu userii din banned.

Daca se doreste alterarea informatiei din certificate se umbla in build.xml in targeturile ca si keystore.Dupa care se dau comenzile ant cleankeystore, ant ca, ant keystore 

Precizare: daca un user este inregistrat pe mai mutle servere, cand trimite un mesaj acesta trimite mesaje pe toate serverele pe care este autentificat.
