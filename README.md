FICHE MONGODB - SQUELETTES (ancien TP noté)

MAJUSCULES = à remplacer. Tout le reste se copie tel quel.
COLLECTION = le nom de ta collection : à changer dans chaque requête, ce n'est pas répété.

Pour chaque requête :
  Sert à    = ce que fait la requête
  À changer = ce que tu remplaces dans le squelette
  A         = la requête de l'annale (celles qui plantaient sont déjà corrigées)
  S         = le squelette

------------------------------------------------------------
1. Version de MongoDB

Sert à    : afficher la version du serveur MongoDB.
À changer : rien.

   db.version()

------------------------------------------------------------
2 et 4. Dernier document inséré

Sert à    : afficher le dernier document ajouté. L'_id grandit avec le temps : on trie du plus
            grand au plus petit (-1) et on garde 1 résultat.
À changer : rien. Pour les N derniers, mettre N dans limit.

A: db.user.find().sort({ _id: -1 }).limit(1)

S: db.COLLECTION.find().sort({ _id: -1 }).limit(1)

------------------------------------------------------------
3. Insérer plusieurs documents

Sert à    : ajouter plusieurs documents d'un coup. Pour un seul : insertOne({ ... }).
À changer : les CHAMP et les VALEUR ; une ligne { ... } par document. Texte entre guillemets,
            nombre sans, date avec new Date("AAAA-MM-JJ").

A: db.user.insertMany([
     { name: "Michel", email: "michel@gmail.com", birthdate: new Date("2000-01-16") },
     { name: "Bernard", email: "bernard@proton.me", birthdate: new Date("1999-02-17") }
   ])

S: db.COLLECTION.insertMany([
     { CHAMP1: VALEUR, CHAMP2: VALEUR },
     { CHAMP1: VALEUR, CHAMP2: VALEUR }
   ])

------------------------------------------------------------
5. Ajouter des champs à tous les documents

Sert à    : créer un nouveau champ dans tous les documents. La première accolade vide {} veut
            dire « tous les documents ».
À changer : NOUVEAU_CHAMP = le nom du champ à créer ; VALEUR = sa valeur de départ. Plusieurs
            champs : les séparer par des virgules.

A: db.user.updateMany({}, { $set: { street: 1, city: 1, zipcode: 1, country: 1, phone: 1, company: 1 } })

S: db.COLLECTION.updateMany({}, { $set: { NOUVEAU_CHAMP: VALEUR } })

------------------------------------------------------------
6. Importer un CSV

Sert à    : charger dans la collection les données du fichier fourni.
À changer : rien à taper : ça se fait avec les boutons de Compass.

   Compass : ouvrir la collection > ADD DATA > Import JSON or CSV file

------------------------------------------------------------
7. Plus de N ans

Sert à    : garder ceux qui ont plus de N ans. On calcule la date d'il y a N ans, puis on garde
            les dates de naissance qui sont avant ($lt).
À changer : CHAMP_DATE = le champ date de naissance ; N = l'âge. Pour « moins de N ans » : $gt à
            la place de $lt.

A: db.user.find({ birthdate: { $lt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) } })

S: db.COLLECTION.find({ CHAMP_DATE: { $lt: new Date(new Date().setFullYear(new Date().getFullYear() - N)) } })

------------------------------------------------------------
8. Texte qui commence par... + tri

Sert à    : garder les documents dont un champ commence par un texte, puis les trier.
À changer : CHAMP = le champ texte ; TEXTE = le début cherché (entre les / /, sans guillemets) ;
            CHAMP_TRI = le champ du tri. 1 = croissant, -1 = décroissant.

A: db.user.find({ email: /^j/i }).sort({ birthdate: 1 })

S: db.COLLECTION.find({ CHAMP: /^TEXTE/ }).sort({ CHAMP_TRI: 1 })

------------------------------------------------------------
9. Texte, sans tenir compte des majuscules

Sert à    : trouver un mot, qu'il soit écrit en majuscules ou en minuscules. C'est le i après la
            regex qui fait ça.
À changer : CHAMP = le champ texte ; TEXTE = le mot cherché.

A: db.user.find({ country: /France/i })

S: db.COLLECTION.find({ CHAMP: /TEXTE/i })

------------------------------------------------------------
10. Supprimer le plus ancien

Sert à    : supprimer le document qui a la plus petite valeur d'un champ (ici la date de
            naissance la plus ancienne). La partie find().sort().limit(1) va chercher cette
            valeur, deleteOne supprime le document qui la porte.
À changer : CHAMP (3 fois, le même) = le champ qui sert à choisir. Dans sort : 1 = la plus
            petite valeur, -1 = la plus grande.

A: db.user.deleteOne({ birthdate: db.user.find().sort({ birthdate: 1 }).limit(1).toArray()[0].birthdate })

S: db.COLLECTION.deleteOne({ CHAMP: db.COLLECTION.find().sort({ CHAMP: 1 }).limit(1).toArray()[0].CHAMP })

------------------------------------------------------------
11. Trouver les doublons

Sert à    : trouver les valeurs présentes plusieurs fois. $group regroupe par le champ et
            compte ; $match garde les groupes de plus de 1.
À changer : CHAMP = le champ où chercher les doublons. Garder le $ et les guillemets : "$email".

A: db.user.aggregate([
     { $group: { _id: "$email", count: { $sum: 1 } } },
     { $match: { count: { $gt: 1 } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: "$CHAMP", count: { $sum: 1 } } },
     { $match: { count: { $gt: 1 } } }
   ])

------------------------------------------------------------
12. Index unique

Sert à    : interdire deux documents avec la même valeur dans un champ. La commande est refusée
            tant qu'il reste des doublons.
À changer : CHAMP = le champ qui doit rester unique.

A: db.user.createIndex({ email: 1 }, { unique: true })

S: db.COLLECTION.createIndex({ CHAMP: 1 }, { unique: true })

------------------------------------------------------------
13. Afficher seulement certains champs

Sert à    : choisir les champs affichés. 1re accolade = le filtre ; 2e accolade = les champs à
            montrer (1).
À changer : CHAMP et VALEUR = le filtre ; CHAMP_A_AFFICHER et AUTRE_CHAMP = les champs voulus.
            Ajouter _id: 0 pour cacher l'_id.

A: db.user.find({ name: "Jane" }, { email: 1, name: 1 })

S: db.COLLECTION.find({ CHAMP: VALEUR }, { CHAMP_A_AFFICHER: 1, AUTRE_CHAMP: 1 })

------------------------------------------------------------
14. Créer une autre collection

Sert à    : créer une deuxième collection (5 groupes dans l'annale). Elle se crée toute seule à
            la première insertion.
À changer : NOUVELLE_COLLECTION = son nom ; les CHAMP et les VALEUR de chaque document.

A: db.group.insertMany([
     { reference: "admin", name: "Admin", description: "Groupe Administrateur", level: 1 },
     { reference: "coordinator", name: "Coordinateur", description: "Groupe de Coordination", level: 2 }
   ])

S: db.NOUVELLE_COLLECTION.insertMany([
     { CHAMP1: VALEUR, CHAMP2: VALEUR },
     { CHAMP1: VALEUR, CHAMP2: VALEUR }
   ])

------------------------------------------------------------
15a. Modifier un document précis

Sert à    : changer la valeur d'un champ dans UN document. $set crée le champ s'il n'existe pas
            encore.
À changer : CHAMP et VALEUR = comment trouver le document ; CHAMP_A_MODIFIER et
            NOUVELLE_VALEUR = ce qu'on y met.

A: db.user.updateOne({ name: "Jim" }, { $set: { group: "admin" } })

S: db.COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
15b. Modifier le premier selon un tri

Sert à    : modifier un seul document, choisi par un tri (ici : le plus âgé qui n'a pas encore
            de groupe).
À changer : CHAMP et VALEUR = le filtre ; CHAMP_A_MODIFIER et NOUVELLE_VALEUR ; CHAMP_TRI = le
            champ qui décide lequel est pris (1 = le plus petit, -1 = le plus grand).

A: db.user.findOneAndUpdate({ group: { $exists: false } }, { $set: { group: "secretariat" } }, { sort: { birthdate: 1 } })

S: db.COLLECTION.findOneAndUpdate({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } }, { sort: { CHAMP_TRI: 1 } })

------------------------------------------------------------
15c. Modifier tous ceux qui n'ont pas encore le champ

Sert à    : donner une valeur à tous les documents où le champ n'existe pas encore ($exists:
            false).
À changer : CHAMP (2 fois, le même) et VALEUR.

A: db.user.updateMany({ group: { $exists: false } }, { $set: { group: "animateur" } })

S: db.COLLECTION.updateMany({ CHAMP: { $exists: false } }, { $set: { CHAMP: VALEUR } })

------------------------------------------------------------
16. Compter avec plusieurs conditions

Sert à    : compter les documents qui respectent toutes les conditions. La virgule veut dire ET.
À changer : CHAMP1 et VALEUR = 1re condition ; CHAMP2 et VALEUR = 2e condition. $gt = plus
            grand, $lt = plus petit.

A: db.user.countDocuments({ group: "animateur", birthdate: { $gt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) } })

S: db.COLLECTION.countDocuments({ CHAMP1: VALEUR, CHAMP2: { $gt: VALEUR } })

------------------------------------------------------------
17. Compter + nom qui commence par une lettre

Sert à    : le même comptage, avec une condition en plus sur le début d'un texte.
À changer : comme la 16, plus CHAMP3 = le champ texte et LETTRE = la lettre du début.

A: db.user.countDocuments({ group: "animateur", birthdate: { $gt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) }, name: /^J/ })

S: db.COLLECTION.countDocuments({ CHAMP1: VALEUR, CHAMP2: { $gt: VALEUR }, CHAMP3: /^LETTRE/ })

------------------------------------------------------------
18. Âge moyen après un filtre

Sert à    : calculer l'âge moyen d'une partie des documents. $match filtre ; $group avec _id:
            null met tout dans un seul groupe ; $avg fait la moyenne. Soustraire deux dates
            donne des millisecondes, la division les change en années.
À changer : CHAMP et VALEUR = le filtre ; NOM_RESULTAT = le nom du résultat (au choix) ;
            CHAMP_DATE = le champ date (garder "$...").

A: db.user.aggregate([
     { $match: { group: "animateur", birthdate: { $gt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) } } },
     { $group: { _id: null, averageAge: { $avg: { $divide: [ { $subtract: [new Date(), "$birthdate"] }, 1000 * 60 * 60 * 24 * 365.25 ] } } } }
   ])

S: db.COLLECTION.aggregate([
     { $match: { CHAMP: VALEUR } },
     { $group: { _id: null, NOM_RESULTAT: { $avg: { $divide: [ { $subtract: [new Date(), "$CHAMP_DATE"] }, 1000 * 60 * 60 * 24 * 365.25 ] } } } }
   ])

------------------------------------------------------------
19. Les N premiers selon un tri

Sert à    : garder les N premiers après un tri (ici les 2 plus âgés d'un groupe).
À changer : CHAMP et VALEUR = le filtre ; CHAMP_TRI = le champ du tri ; N = combien on en garde.

A: db.user.find({ group: "animateur" }).sort({ birthdate: 1 }).limit(2)

S: db.COLLECTION.find({ CHAMP: VALEUR }).sort({ CHAMP_TRI: 1 }).limit(N)

------------------------------------------------------------
20. Modifier plusieurs documents

Sert à    : modifier d'un coup les documents qui respectent une condition OU une autre ($or).
À changer : CHAMP, VALEUR1, VALEUR2 = les documents visés ; CHAMP_A_MODIFIER et
            NOUVELLE_VALEUR = ce qu'on y met.

A: db.user.updateMany({ $or: [ { name: "Jil Aktem" }, { name: "Joey" } ] }, { $set: { group: "coordinator" } })

S: db.COLLECTION.updateMany({ $or: [ { CHAMP: VALEUR1 }, { CHAMP: VALEUR2 } ] }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
21. Jointure entre deux collections

Sert à    : afficher chaque document avec les infos de l'autre collection. $lookup fait le
            lien ; $unwind transforme le tableau obtenu en objet ; $sort trie.
À changer : AUTRE_COLLECTION = la collection à joindre ; CHAMP_ICI = le champ de COLLECTION qui
            fait le lien ; CHAMP_LA_BAS = le champ correspondant dans AUTRE_COLLECTION ;
            NOM_RESULTAT = le nom du champ qui reçoit les infos (au choix, le même partout).

A: db.user.aggregate([
     { $lookup: { from: "group", localField: "group", foreignField: "reference", as: "groupDetails" } },
     { $unwind: "$groupDetails" },
     { $sort: { "groupDetails.name": 1, email: 1 } }
   ])

S: db.COLLECTION.aggregate([
     { $lookup: { from: "AUTRE_COLLECTION", localField: "CHAMP_ICI", foreignField: "CHAMP_LA_BAS", as: "NOM_RESULTAT" } },
     { $unwind: "$NOM_RESULTAT" },
     { $sort: { "NOM_RESULTAT.CHAMP": 1, CHAMP: 1 } }
   ])

------------------------------------------------------------
22. Nombre et moyenne par groupe

Sert à    : compter et faire une moyenne pour chaque catégorie. _id = le champ de regroupement ;
            $sum: 1 compte ; $avg fait la moyenne.
À changer : CHAMP_GROUPE = le champ qui fait les catégories ; NOM_MOYENNE = au choix ;
            CHAMP_NOMBRE = le champ à moyenner. Pour un âge : remplacer "$CHAMP_NOMBRE" par le
            $divide de la question 18.

A: db.user.aggregate([
     { $group: { _id: "$group", count: { $sum: 1 }, averageAge: { $avg: { $divide: [ { $subtract: [new Date(), "$birthdate"] }, 1000 * 60 * 60 * 24 * 365.25 ] } } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: "$CHAMP_GROUPE", count: { $sum: 1 }, NOM_MOYENNE: { $avg: "$CHAMP_NOMBRE" } } }
   ])

------------------------------------------------------------
23. Enregistrer un résultat dans une autre collection

Sert à    : garder le résultat d'une agrégation dans une collection. aggregate calcule, toArray
            en fait une liste, insertMany l'enregistre.
À changer : COLLECTION_ARCHIVE = la collection où enregistrer ; ETAPES = les étapes de ton
            agrégation.

A: db.archive.insertMany(
     db.user.aggregate([
       { $group: { _id: "$group", count: { $sum: 1 } } }
     ]).toArray()
   )

S: db.COLLECTION_ARCHIVE.insertMany(
     db.COLLECTION.aggregate([
       ETAPES
     ]).toArray()
   )

------------------------------------------------------------
24. Pas de réponse dans l'annale

------------------------------------------------------------
25. Transaction : insérer

Sert à    : faire des écritures qui sont toutes validées au commitTransaction, ou toutes
            annulées.
À changer : BASE = le nom de ta base (la commande db l'affiche) ; COLLECTION ; le document à
            insérer. Les 4 autres lignes ne changent jamais.

A: session = db.getMongo().startSession()
   session.startTransaction()
   session.getDatabase("TPMongo").user.insertOne({ name: "Alice", birthdate: new Date(), group: "Assistante" })
   session.commitTransaction()
   session.endSession()

S: session = db.getMongo().startSession()
   session.startTransaction()
   session.getDatabase("BASE").COLLECTION.insertOne({ CHAMP: VALEUR })
   session.commitTransaction()
   session.endSession()

------------------------------------------------------------
26. Transaction : modifier

Sert à    : la même transaction avec une modification : seule la 3e ligne change.
À changer : BASE ; COLLECTION ; CHAMP et VALEUR = le document visé ; CHAMP_A_MODIFIER et
            NOUVELLE_VALEUR.

A: session.getDatabase("TPMongo").group.updateOne({ name: "Coordinateur" }, { $set: { name: "Regulateur" } })

S: session.getDatabase("BASE").COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })


A-A-A--A-A-A-A-A-A-A-A-A-A-A-A--A-A-A-A-A--A-A-A-A-A-A-A-A--A-A-A-A-A-A-A--A-A-A-A-A-A--A-A-A-A-A--A-A-A-A-A-A-A-A--A-A-A-A-A-A-A-A--A-A-A-A-A-A-A-A--A-A-A-A-A-A-A-----------------------------------------------------------------------------------------------------------------------------------------------------------------

FICHE MONGODB - SQUELETTES (requêtes du TP fait en TD)

MAJUSCULES = à remplacer. Tout le reste se copie tel quel.
COLLECTION = le nom de ta collection : à changer dans chaque requête, ce n'est pas répété.

Pour chaque requête :
  Sert à    = ce que fait la requête
  À changer = ce que tu remplaces dans le squelette
  T         = la requête du TD (les erreurs du corrigé sont déjà corrigées)
  S         = le squelette
Les numéros sont ceux du sujet du TP.


============================================================
BASE, COLLECTIONS, INSERTION
============================================================

------------------------------------------------------------
Commandes du shell

   use BASE                     choisir la base (créée à la première insertion)
   show dbs                     lister les bases
   show collections             lister les collections
   db.COLLECTION.findOne()      voir à quoi ressemble un document

------------------------------------------------------------
Insérer un document

Sert à    : ajouter un document. Un champ peut contenir un texte, un nombre, un tableau [ ], un
            objet { } ou une date.
À changer : les noms de champs et les valeurs ; enlever les lignes dont tu n'as pas besoin.

T: db.etudiants.insertOne({
     _id: 1,
     nom: "DURAND",
     prenoms: ["Alain", "Paul"],
     adresse: { numero: "12", rue: "Rue Arc en Ciel", ville: "Annecy", cp: "74000" },
     "date naissance": ISODate("1977-08-01T15:00:00Z")
   })

S: db.COLLECTION.insertOne({
     CHAMP: VALEUR,
     CHAMP_TABLEAU: [VALEUR1, VALEUR2],
     CHAMP_OBJET: { SOUS_CHAMP: VALEUR },
     CHAMP_DATE: ISODate("AAAA-MM-JJ")
   })

------------------------------------------------------------
Insérer plusieurs documents

Sert à    : ajouter plusieurs documents d'un coup.
À changer : une ligne { ... } par document, avec ses champs et ses valeurs.

T: db.etudiants.insertMany([
     { nom: "LEROY", prenoms: ["Sophie"], adresse: { numero: "5", rue: "Rue Nationale", ville: "Paris", cp: "75001" }, annee_experience: 1 },
     { nom: "BENALI", prenoms: ["Karim"], adresse: { numero: "10", rue: "Avenue Victor Hugo", ville: "Marseille", cp: "13008" }, annee_experience: 5 }
   ])

S: db.COLLECTION.insertMany([
     { CHAMP1: VALEUR, CHAMP2: VALEUR },
     { CHAMP1: VALEUR, CHAMP2: VALEUR }
   ])

------------------------------------------------------------
Chercher par un champ

Sert à    : afficher les documents où un champ vaut une valeur.
À changer : CHAMP et VALEUR (texte entre guillemets, nombre sans).

T: db.etudiants.find({ nom: "DURAND" })

S: db.COLLECTION.find({ CHAMP: VALEUR })


============================================================
OPÉRATEURS (exercices 1 à 13)
============================================================

------------------------------------------------------------
1. Habitant à Paris

Sert à    : filtrer sur un champ rangé dans un objet (la ville est dans adresse). On écrit
            "objet.champ" entre guillemets.
À changer : CHAMP_OBJET = l'objet ; SOUS_CHAMP = le champ dedans ; VALEUR.

T: db.etudiants.find({ "adresse.ville": "Paris" })

S: db.COLLECTION.find({ "CHAMP_OBJET.SOUS_CHAMP": VALEUR })

------------------------------------------------------------
2. Habitant à Lyon, sans afficher l'ID

Sert à    : afficher les documents sans leur _id. La 2e accolade choisit ce qu'on affiche : 0 =
            cacher.
À changer : CHAMP et VALEUR = le filtre.

T: db.etudiants.find({ "adresse.ville": "Lyon" }, { _id: 0 })

S: db.COLLECTION.find({ CHAMP: VALEUR }, { _id: 0 })

------------------------------------------------------------
3. Habitant à Lyon ou à Marseille

Sert à    : garder les documents qui respectent une condition OU une autre ($or).
À changer : CHAMP, VALEUR1, VALEUR2. Les deux conditions peuvent porter sur des champs
            différents.

T: db.etudiants.find({ $or: [ { "adresse.ville": "Lyon" }, { "adresse.ville": "Marseille" } ] })

S: db.COLLECTION.find({ $or: [ { CHAMP: VALEUR1 }, { CHAMP: VALEUR2 } ] })

------------------------------------------------------------
4. Même requête, triée par expérience décroissante

Sert à    : trier le résultat. -1 = du plus grand au plus petit, 1 = l'inverse.
À changer : comme la 3, plus CHAMP_TRI = le champ du tri.

T: db.etudiants.find({ $or: [ { "adresse.ville": "Lyon" }, { "adresse.ville": "Marseille" } ] }).sort({ annee_experience: -1 })

S: db.COLLECTION.find({ $or: [ { CHAMP: VALEUR1 }, { CHAMP: VALEUR2 } ] }).sort({ CHAMP_TRI: -1 })

------------------------------------------------------------
5. Prénom dans une liste

Sert à    : garder les documents dont le champ vaut une des valeurs de la liste ($in).
À changer : CHAMP ; la liste des valeurs entre [ ].

T: db.etudiants.find({ prenoms: { $in: ["Paul", "Sophie"] } })

S: db.COLLECTION.find({ CHAMP: { $in: [VALEUR1, VALEUR2] } })

------------------------------------------------------------
6. Deux conditions

Sert à    : garder les documents qui respectent les deux conditions. La virgule veut dire ET ;
            $gte = supérieur ou égal.
À changer : CHAMP1 et VALEUR = 1re condition ; CHAMP2 et VALEUR = 2e condition.

T: db.etudiants.find({ "adresse.ville": "Paris", annee_experience: { $gte: 2 } })

S: db.COLLECTION.find({ CHAMP1: VALEUR, CHAMP2: { $gte: VALEUR } })

------------------------------------------------------------
7. N'habitant pas à Lyon

Sert à    : garder les documents où le champ est différent d'une valeur ($ne).
À changer : CHAMP et VALEUR.

T: db.etudiants.find({ "adresse.ville": { $ne: "Lyon" } })

S: db.COLLECTION.find({ CHAMP: { $ne: VALEUR } })

------------------------------------------------------------
8. N'habitant ni à Paris ni à Marseille

Sert à    : garder les documents où le champ ne vaut aucune des valeurs de la liste ($nin).
À changer : CHAMP ; la liste des valeurs à exclure.

T: db.etudiants.find({ "adresse.ville": { $nin: ["Paris", "Marseille"] } })

S: db.COLLECTION.find({ CHAMP: { $nin: [VALEUR1, VALEUR2] } })

------------------------------------------------------------
9. Aucun prénom n'est Paul ou Alain

Sert à    : pareil sur un tableau : garde les documents dont le tableau ne contient aucune des
            valeurs.
À changer : CHAMP_TABLEAU ; la liste des valeurs à exclure.

T: db.etudiants.find({ prenoms: { $nin: ["Paul", "Alain"] } })

S: db.COLLECTION.find({ CHAMP_TABLEAU: { $nin: [VALEUR1, VALEUR2] } })

------------------------------------------------------------
10. Habitant à Lyon mais pas dans la rue "Rue de la Paix"

Sert à    : combiner « égal à » sur un champ ET « différent de » sur un autre.
À changer : CHAMP1 et VALEUR = ce qui doit être égal ; CHAMP2 et VALEUR = ce qui doit être
            différent.

T: db.etudiants.find({ "adresse.ville": "Lyon", "adresse.rue": { $ne: "Rue de la Paix" } })

S: db.COLLECTION.find({ CHAMP1: VALEUR, CHAMP2: { $ne: VALEUR } })

------------------------------------------------------------
11. Plus de 3 ans d'expérience

Sert à    : comparer un nombre. $gt = plus grand, $lt = plus petit, $gte et $lte = ou égal.
À changer : CHAMP, VALEUR, et l'opérateur selon la question.

T: db.etudiants.find({ annee_experience: { $gt: 3 } })

S: db.COLLECTION.find({ CHAMP: { $gt: VALEUR } })

------------------------------------------------------------
12. Le champ notes existe

Sert à    : garder les documents qui possèdent ce champ. Avec false : ceux qui ne l'ont pas.
À changer : CHAMP.

T: db.etudiants.find({ notes: { $exists: true } })

S: db.COLLECTION.find({ CHAMP: { $exists: true } })

------------------------------------------------------------
13. Un prénom commence par A

Sert à    : chercher un texte. /^A/ = commence par A, /A$/ = finit par A, /A/ = contient A.
À changer : CHAMP ; TEXTE (entre les / /, sans guillemets).

T: db.etudiants.find({ prenoms: /^A/ })

S: db.COLLECTION.find({ CHAMP: /^TEXTE/ })


============================================================
AGRÉGATIONS (exercices 14 à 22)
============================================================

------------------------------------------------------------
14. À partir du numéro 2

Sert à    : sauter les N premiers documents (skip). Les deux lignes font la même chose : avec
            find, ou avec une agrégation.
À changer : N = combien on en saute.

T: db.etudiants.find().skip(2)
   db.etudiants.aggregate([ { $skip: 2 } ])

S: db.COLLECTION.find().skip(N)
   db.COLLECTION.aggregate([ { $skip: N } ])

------------------------------------------------------------
15. Trier par expérience décroissante

Sert à    : trier tous les documents. Les deux lignes font la même chose.
À changer : CHAMP_TRI ; -1 = décroissant, 1 = croissant.

T: db.etudiants.find().sort({ annee_experience: -1 })
   db.etudiants.aggregate([ { $sort: { annee_experience: -1 } } ])

S: db.COLLECTION.find().sort({ CHAMP_TRI: -1 })
   db.COLLECTION.aggregate([ { $sort: { CHAMP_TRI: -1 } } ])

------------------------------------------------------------
16. Moyenne d'expérience de tous les étudiants

Sert à    : calculer une moyenne sur toute la collection. _id: null = un seul groupe pour tout
            le monde.
À changer : NOM_RESULTAT = le nom du résultat (au choix) ; CHAMP_NOMBRE = le champ à moyenner
            (garder "$...").

T: db.etudiants.aggregate([
     { $group: { _id: null, moyenne_experience: { $avg: "$annee_experience" } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: null, NOM_RESULTAT: { $avg: "$CHAMP_NOMBRE" } } }
   ])

------------------------------------------------------------
17. Moyenne d'expérience par ville

Sert à    : calculer une moyenne pour chaque catégorie. _id = le champ de regroupement.
À changer : CHAMP_GROUPE = le champ qui fait les catégories ; NOM_RESULTAT ; CHAMP_NOMBRE.

T: db.etudiants.aggregate([
     { $group: { _id: "$adresse.ville", moyenne_experience: { $avg: "$annee_experience" } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: "$CHAMP_GROUPE", NOM_RESULTAT: { $avg: "$CHAMP_NOMBRE" } } }
   ])

------------------------------------------------------------
18. Moyenne d'expérience par ville et code postal

Sert à    : regrouper sur deux champs à la fois : une ligne par couple ville + code postal.
À changer : NOM1 et NOM2 = au choix ; CHAMP_GROUPE1 et CHAMP_GROUPE2 = les deux champs ;
            NOM_RESULTAT ; CHAMP_NOMBRE.

T: db.etudiants.aggregate([
     { $group: { _id: { ville: "$adresse.ville", cp: "$adresse.cp" }, moyenne_experience: { $avg: "$annee_experience" } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: { NOM1: "$CHAMP_GROUPE1", NOM2: "$CHAMP_GROUPE2" }, NOM_RESULTAT: { $avg: "$CHAMP_NOMBRE" } } }
   ])

------------------------------------------------------------
19. Nombre d'étudiants habitant à Paris

Sert à    : compter les documents d'un filtre. Les deux lignes donnent le même nombre.
À changer : CHAMP et VALEUR = le filtre ; NOM_RESULTAT = le nom du compteur (au choix).

T: db.etudiants.countDocuments({ "adresse.ville": "Paris" })
   db.etudiants.aggregate([ { $match: { "adresse.ville": "Paris" } }, { $count: "nb_etudiants_paris" } ])

S: db.COLLECTION.countDocuments({ CHAMP: VALEUR })
   db.COLLECTION.aggregate([ { $match: { CHAMP: VALEUR } }, { $count: "NOM_RESULTAT" } ])

------------------------------------------------------------
20. Nombre d'étudiants dont le champ notes est présent

Sert à    : compter les documents qui possèdent un champ.
À changer : CHAMP.

T: db.etudiants.countDocuments({ notes: { $exists: true } })

S: db.COLLECTION.countDocuments({ CHAMP: { $exists: true } })

------------------------------------------------------------
21. Nombre de noms distincts

Sert à    : compter les valeurs différentes d'un champ. Sans .length, on obtient la liste des
            valeurs.
À changer : CHAMP ; NOM_RESULTAT.

T: db.etudiants.distinct("nom").length
   db.etudiants.aggregate([ { $group: { _id: "$nom" } }, { $count: "noms_distincts" } ])

S: db.COLLECTION.distinct("CHAMP").length
   db.COLLECTION.aggregate([ { $group: { _id: "$CHAMP" } }, { $count: "NOM_RESULTAT" } ])

------------------------------------------------------------
22. Nombre d'étudiants par prénom

Sert à    : compter par valeur d'un tableau. $unwind fait une ligne par élément du tableau ;
            $group compte ; $sort trie.
À changer : CHAMP_TABLEAU (2 fois, le même) ; NOM_RESULTAT (2 fois, le même).

T: db.etudiants.aggregate([
     { $unwind: "$prenoms" },
     { $group: { _id: "$prenoms", nb_etudiants: { $sum: 1 } } },
     { $sort: { nb_etudiants: -1 } }
   ])

S: db.COLLECTION.aggregate([
     { $unwind: "$CHAMP_TABLEAU" },
     { $group: { _id: "$CHAMP_TABLEAU", NOM_RESULTAT: { $sum: 1 } } },
     { $sort: { NOM_RESULTAT: -1 } }
   ])


============================================================
MODIFICATION ET SUPPRESSION (exercices 23 à 25)
============================================================

------------------------------------------------------------
23. Mettre à jour un étudiant

Sert à    : modifier UN document. 1re accolade = lequel ; $set = ce qu'on change.
À changer : CHAMP et VALEUR = le document visé ; CHAMP_A_MODIFIER et NOUVELLE_VALEUR.

T: db.etudiants.updateOne({ _id: 2 }, { $set: { nom: "DURAND2" } })

S: db.COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
24. Mise à jour en masse

Sert à    : modifier TOUS les documents du filtre.
À changer : CHAMP et VALEUR = les documents visés ; CHAMP_A_MODIFIER et NOUVELLE_VALEUR.

T: db.etudiants.updateMany({ "adresse.ville": "Paris" }, { $set: { "adresse.ville": "PARIS" } })

S: db.COLLECTION.updateMany({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
25. Supprimer un étudiant

Sert à    : supprimer UN document. deleteMany supprime tous ceux du filtre.
À changer : CHAMP et VALEUR = le document à supprimer.

T: db.etudiants.deleteOne({ _id: 2 })

S: db.COLLECTION.deleteOne({ CHAMP: VALEUR })


============================================================
MODÉLISATION ET JOINTURES (exercices 26 à 30)
============================================================

------------------------------------------------------------
26. Dupliquer une collection

Sert à    : copier une collection. $match: {} prend tout ; $out écrit le résultat dans une
            nouvelle collection.
À changer : NOUVELLE_COLLECTION = le nom de la copie.

T: db.etudiants.aggregate([ { $match: {} }, { $out: "etudiants2" } ])

S: db.COLLECTION.aggregate([ { $match: {} }, { $out: "NOUVELLE_COLLECTION" } ])

------------------------------------------------------------
27. Créer la collection formations

Sert à    : créer une deuxième collection, à relier ensuite aux étudiants (sigle, intitulé,
            année de création, 3 documents).
À changer : NOUVELLE_COLLECTION ; les champs et les valeurs.

T: db.formations.insertMany([
     { sigle: "dutinfo", intitule: "DUT Informatique", annee_creation: 1990 },
     { sigle: "cyber", intitule: "Informatique et CyberSécurité", annee_creation: 2015 },
     { sigle: "cgp", intitule: "Chimie et Génie des procédés", annee_creation: 1990 }
   ])

S: db.NOUVELLE_COLLECTION.insertMany([
     { CHAMP1: VALEUR, CHAMP2: VALEUR, CHAMP3: VALEUR },
     { CHAMP1: VALEUR, CHAMP2: VALEUR, CHAMP3: VALEUR }
   ])

------------------------------------------------------------
28. Ajouter aux étudiants un champ formation

Sert à    : copier dans un étudiant une partie d'une formation. 1re ligne : on récupère la
            formation dans f. 2e ligne : on écrit son _id et son intitulé dans l'étudiant.
À changer : AUTRE_COLLECTION et son filtre = le document à récupérer ; COLLECTION et son
            filtre = le document à modifier ; NOUVEAU_CHAMP ; SOUS_CHAMP = le champ recopié. f
            se copie tel quel.

T: var f = db.formations.findOne({ sigle: "dutinfo" })
   db.etudiants.updateOne({ nom: "DURAND" }, { $set: { formation: { _id: f._id, intitule: f.intitule } } })

S: var f = db.AUTRE_COLLECTION.findOne({ CHAMP: VALEUR })
   db.COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { NOUVEAU_CHAMP: { _id: f._id, SOUS_CHAMP: f.SOUS_CHAMP } } })

------------------------------------------------------------
28 bis. Le faire pour tous les étudiants avec une boucle

Sert à    : faire une modification sur chaque document, un par un. C'est le code « dynamique »
            proposé dans le sujet.
À changer : CHAMP_A_MODIFIER et NOUVELLE_VALEUR. liste et i se copient tels quels.

T: var formations = db.formations.find().toArray()
   var etudiants = db.etudiants.find().toArray()
   for (var i = 0; i < etudiants.length; i++) {
     var f = formations[i % formations.length]
     db.etudiants.updateOne({ _id: etudiants[i]._id }, { $set: { formation: { _id: f._id, intitule: f.intitule } } })
   }

S: var liste = db.COLLECTION.find().toArray()
   for (var i = 0; i < liste.length; i++) {
     db.COLLECTION.updateOne({ _id: liste[i]._id }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })
   }

------------------------------------------------------------
29. Ajouter le champ formationId

Sert à    : relier un étudiant à sa formation en ne gardant que l'_id de la formation (une
            référence).
À changer : AUTRE_COLLECTION et son filtre ; COLLECTION et son filtre ; NOUVEAU_CHAMP = le champ
            qui reçoit l'_id.

T: var f = db.formations.findOne({ sigle: "cyber" })
   db.etudiants2.updateOne({ nom: "EVENOT" }, { $set: { formationId: f._id } })

S: var f = db.AUTRE_COLLECTION.findOne({ CHAMP: VALEUR })
   db.COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { NOUVEAU_CHAMP: f._id } })

------------------------------------------------------------
30a. Jointure en partant d'etudiants2

Sert à    : afficher chaque étudiant avec sa formation. $lookup fait le lien ; $replaceRoot met
            les champs de la formation à côté de ceux de l'étudiant ; $project cache (0) ce
            qu'on ne veut pas voir.
À changer : AUTRE_COLLECTION ; CHAMP_ICI = le champ de COLLECTION qui fait le lien ;
            CHAMP_LA_BAS = le champ correspondant en face ; NOM_RESULTAT (3 fois, le même) ; la
            liste des champs à cacher.

T: db.etudiants2.aggregate([
     { $lookup: { from: "formations", localField: "formationId", foreignField: "_id", as: "formationEtu" } },
     { $replaceRoot: { newRoot: { $mergeObjects: [ { $arrayElemAt: ["$formationEtu", 0] }, "$$ROOT" ] } } },
     { $project: { _id: 0, sigle: 0, annee_creation: 0, adresse: 0, "date naissance": 0, notes: 0, annee_experience: 0, formationId: 0, formationEtu: 0 } }
   ])

S: db.COLLECTION.aggregate([
     { $lookup: { from: "AUTRE_COLLECTION", localField: "CHAMP_ICI", foreignField: "CHAMP_LA_BAS", as: "NOM_RESULTAT" } },
     { $replaceRoot: { newRoot: { $mergeObjects: [ { $arrayElemAt: ["$NOM_RESULTAT", 0] }, "$$ROOT" ] } } },
     { $project: { _id: 0, CHAMP_A_CACHER: 0, AUTRE_CHAMP_A_CACHER: 0, NOM_RESULTAT: 0 } }
   ])

------------------------------------------------------------
30b. Jointure en partant de formations

Sert à    : la même jointure dans l'autre sens. $unwind fait une ligne par étudiant ; $project
            choisit les champs affichés.
À changer : les deux collections sont inversées ; NOM_RESULTAT (4 fois, le même) ; CHAMP = le
            champ de la formation à afficher ; CHAMP1 et CHAMP2 = les champs de l'étudiant à
            afficher ; NOM1 et NOM2 = leurs noms à l'affichage.

T: db.formations.aggregate([
     { $lookup: { from: "etudiants2", localField: "_id", foreignField: "formationId", as: "etu" } },
     { $unwind: "$etu" },
     { $project: { _id: 0, intitule: 1, nom: "$etu.nom", prenoms: "$etu.prenoms" } }
   ])

S: db.AUTRE_COLLECTION.aggregate([
     { $lookup: { from: "COLLECTION", localField: "CHAMP_LA_BAS", foreignField: "CHAMP_ICI", as: "NOM_RESULTAT" } },
     { $unwind: "$NOM_RESULTAT" },
     { $project: { _id: 0, CHAMP: 1, NOM1: "$NOM_RESULTAT.CHAMP1", NOM2: "$NOM_RESULTAT.CHAMP2" } }
   ])


============================================================
TRANSACTIONS (exercices 31 et 32)
============================================================

------------------------------------------------------------
31. Transaction : insérer une formation ET 2 étudiants de cette formation

Sert à    : insérer plusieurs documents liés : tout est validé au commitTransaction, sinon rien.
            res.insertedId = l'_id du document inséré juste avant.
À changer : BASE = le nom de ta base ; COLLECTION1 et son document ; COLLECTION2 et ses
            documents ; CHAMP_LIEN = le champ qui pointe vers le premier document. Les lignes
            session... ne changent jamais.

T: session = db.getMongo().startSession()
   session.startTransaction()
   var res = session.getDatabase("bdetudiants").formations.insertOne({ sigle: "cgp", intitule: "Chimie et Génie des procédés", annee_creation: 1990 })
   session.getDatabase("bdetudiants").etudiants2.insertMany([
     { nom: "THUREAUX", prenoms: ["Boris"], formationId: res.insertedId },
     { nom: "DUPONT", prenoms: ["Théodore"], formationId: res.insertedId }
   ])
   session.commitTransaction()
   session.endSession()

S: session = db.getMongo().startSession()
   session.startTransaction()
   var res = session.getDatabase("BASE").COLLECTION1.insertOne({ CHAMP: VALEUR })
   session.getDatabase("BASE").COLLECTION2.insertMany([
     { CHAMP: VALEUR, CHAMP_LIEN: res.insertedId },
     { CHAMP: VALEUR, CHAMP_LIEN: res.insertedId }
   ])
   session.commitTransaction()
   session.endSession()

------------------------------------------------------------
32. Transaction : modifier la formation ET les intitulés chez les étudiants

Sert à    : faire deux modifications qui doivent réussir ensemble.
À changer : BASE ; les deux collections, leurs filtres et leurs $set.

T: session = db.getMongo().startSession()
   session.startTransaction()
   session.getDatabase("bdetudiants").formations.updateOne({ sigle: "dutinfo" }, { $set: { sigle: "butinfo", intitule: "BUT Informatique" } })
   session.getDatabase("bdetudiants").etudiants.updateMany({ "formation.intitule": "DUT Informatique" }, { $set: { "formation.intitule": "BUT Informatique" } })
   session.commitTransaction()
   session.endSession()

S: session = db.getMongo().startSession()
   session.startTransaction()
   session.getDatabase("BASE").COLLECTION1.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })
   session.getDatabase("BASE").COLLECTION2.updateMany({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })
   session.commitTransaction()
   session.endSession()


============================================================
SAUVEGARDE, EXPORT, IMPORT (exercices 33 à 36)
À taper dans le terminal du système, pas dans le shell de Compass.
============================================================

------------------------------------------------------------
33. Sauvegarder la base

Sert à    : sauvegarder toute la base dans un dossier dump/.
À changer : BASE = le nom de ta base.

T: mongodump --db bdetudiants

S: mongodump --db BASE

------------------------------------------------------------
34. Restaurer la base

Sert à    : recréer une base à partir de la sauvegarde.
À changer : NOUVELLE_BASE = le nom de la base recréée ; BASE = celle qui a été sauvegardée.

T: mongorestore --db bdetudiants2 dump/bdetudiants

S: mongorestore --db NOUVELLE_BASE dump/BASE

------------------------------------------------------------
35. Exporter une collection en JSON

Sert à    : écrire une collection dans un fichier JSON.
À changer : BASE, COLLECTION, FICHIER.

T: mongoexport --db bdetudiants --collection etudiants --out etudiants.json

S: mongoexport --db BASE --collection COLLECTION --out FICHIER.json

------------------------------------------------------------
36. Importer un fichier JSON

Sert à    : charger un fichier JSON dans une collection.
À changer : BASE, COLLECTION, FICHIER.

T: mongoimport --db bdetudiants --collection etudiants --file etudiants.json

S: mongoimport --db BASE --collection COLLECTION --file FICHIER.json


============================================================
SCHÉMA DE VALIDATION ET IMPORT (exercices 37 à 40)
============================================================

------------------------------------------------------------
37 et 38. Créer une collection avec un schéma

Sert à    : créer une collection qui refuse les documents mal formés. required = les champs
            obligatoires ; properties = les règles de chaque champ.
À changer : la liste required ; une ligne par champ dans properties. bsonType = le type (string,
            int, array, object) ; minimum et maximum = les bornes ; enum = les valeurs
            permises ; maxItems = la taille maximum du tableau.

T: db.createCollection("movies", {
     validator: {
       $jsonSchema: {
         bsonType: "object",
         required: ["_id", "genre", "title", "year", "country", "director"],
         properties: {
           _id: { bsonType: "string" },
           title: { bsonType: "string" },
           genre: { bsonType: "string" },
           year: { bsonType: "int", minimum: 1950, maximum: 2019 },
           country: { enum: ["USA", "FR", "IT", "DE"] },
           actors: { bsonType: "array", maxItems: 6, items: { bsonType: "object" } }
         }
       }
     }
   })

S: db.createCollection("COLLECTION", {
     validator: {
       $jsonSchema: {
         bsonType: "object",
         required: ["CHAMP1", "CHAMP2"],
         properties: {
           CHAMP_TEXTE: { bsonType: "string" },
           CHAMP_NOMBRE: { bsonType: "int", minimum: MIN, maximum: MAX },
           CHAMP_A_CHOIX: { enum: [VALEUR1, VALEUR2] },
           CHAMP_TABLEAU: { bsonType: "array", maxItems: N, items: { bsonType: "object" } }
         }
       }
     }
   })

------------------------------------------------------------
39. Importer les films

Sert à    : charger le fichier des films (dans le terminal). Les documents refusés par le schéma
            ne sont pas importés.
À changer : BASE, COLLECTION, FICHIER. Ajouter --jsonArray si le fichier commence par [.

T: mongoimport --db bdmovies --collection movies --file movies_references_exporte.json

S: mongoimport --db BASE --collection COLLECTION --file FICHIER.json

------------------------------------------------------------
40. Insérer un document qui ne respecte pas le schéma

Sert à    : vérifier que le schéma bloque. On insère exprès un document faux (ici year: 1940,
            sous le minimum) et on obtient « Document failed validation ».
À changer : mettre une valeur interdite par ton schéma.

T: db.movies.insertOne({ _id: "movie:test", title: "Test", genre: "drama", year: 1940, country: "USA", director: "X" })

S: db.COLLECTION.insertOne({ CHAMP: VALEUR_INTERDITE })


============================================================
INDEX (exercices 41 à 44)
============================================================

------------------------------------------------------------
41 et 42. Créer un index et comparer avant / après avec explain

Sert à    : voir si une requête utilise un index. explain avant l'index : COLLSCAN (toute la
            collection est lue). Après createIndex : IXSCAN (l'index est utilisé).
À changer : CHAMP et VALEUR = la requête testée ; dans createIndex, CHAMP = le même champ.

T: db.movies.find({ year: 1999 }).explain("executionStats")
   db.movies.createIndex({ year: 1 })
   db.movies.find({ year: 1999 }).explain("executionStats")

S: db.COLLECTION.find({ CHAMP: VALEUR }).explain("executionStats")
   db.COLLECTION.createIndex({ CHAMP: 1 })
   db.COLLECTION.find({ CHAMP: VALEUR }).explain("executionStats")

------------------------------------------------------------
Autres commandes sur les index

Sert à    : gérer les index d'une collection. Dans dropIndex, le nom d'un index = le champ suivi
            de _1.

   lister les index         db.COLLECTION.getIndexes()
   supprimer un index       db.COLLECTION.dropIndex("CHAMP_1")
   taille des index         db.COLLECTION.totalIndexSize()
   statistiques             db.COLLECTION.stats()
   vérifier la collection   db.COLLECTION.validate()

------------------------------------------------------------
43. Types d'index

Sert à    : accélérer les recherches selon le type de champ. L'index primaire existe déjà tout
            seul sur _id.

   simple (un champ)            db.COLLECTION.createIndex({ CHAMP: 1 })
   composé (plusieurs champs)   db.COLLECTION.createIndex({ CHAMP1: 1, CHAMP2: -1 })
   multi-key (champ tableau)    db.COLLECTION.createIndex({ CHAMP_TABLEAU: 1 })
   texte (recherche de mots)    db.COLLECTION.createIndex({ CHAMP: "text" })
   géospatial (coordonnées)     db.COLLECTION.createIndex({ CHAMP_POSITION: "2dsphere" })
   haché (hash de la valeur)    db.COLLECTION.createIndex({ CHAMP: "hashed" })

------------------------------------------------------------
44. Options d'index

Sert à    : ajouter une règle à un index : c'est la 2e accolade de createIndex.

   unique (pas de doublon)               db.COLLECTION.createIndex({ CHAMP: 1 }, { unique: true })
   TTL (supprimé après N secondes)       db.COLLECTION.createIndex({ CHAMP_DATE: 1 }, { expireAfterSeconds: N })
   partiel (documents du filtre)         db.COLLECTION.createIndex({ CHAMP: 1 }, { partialFilterExpression: { CHAMP2: { $gte: VALEUR } } })
   sparse (documents qui ont le champ)   db.COLLECTION.createIndex({ CHAMP: 1 }, { sparse: true })
   sans casse (A = a)                    db.COLLECTION.createIndex({ CHAMP: 1 }, { collation: { locale: "fr", strength: 2 } })


