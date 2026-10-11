FICHE MONGODB 

MAJUSCULES = à remplacer (COLLECTION, CHAMP, VALEUR, N, BASE).
Tout le reste se copie tel quel.

A = la requête de l'annale (celles qui plantaient sont déjà corrigées)
S = le squelette

------------------------------------------------------------
1. Version de MongoDB

   db.version()

------------------------------------------------------------
2 et 4. Dernier document inséré

A: db.user.find().sort({ _id: -1 }).limit(1)

S: db.COLLECTION.find().sort({ _id: -1 }).limit(1)

------------------------------------------------------------
3. Insérer plusieurs documents

A: db.user.insertMany([
     { name: "Michel", email: "michel@gmail.com", birthdate: new Date("2000-01-16") },
     { name: "Bernard", email: "bernard@proton.me", birthdate: new Date("1999-02-17") }
   ])

S: db.COLLECTION.insertMany([
     { CHAMP1: VALEUR, CHAMP2: VALEUR },
     { CHAMP1: VALEUR, CHAMP2: VALEUR }
   ])

------------------------------------------------------------
5. Ajouter des champs à tous les documents   ( {} = tous )

A: db.user.updateMany({}, { $set: { street: 1, city: 1, zipcode: 1, country: 1, phone: 1, company: 1 } })

S: db.COLLECTION.updateMany({}, { $set: { NOUVEAU_CHAMP: VALEUR } })

------------------------------------------------------------
6. Importer un CSV

   Compass : ouvrir la collection > ADD DATA > Import JSON or CSV file

------------------------------------------------------------
7. Plus de N ans   ( $lt = plus de N ans, $gt = moins de N ans )

A: db.user.find({ birthdate: { $lt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) } })

S: db.COLLECTION.find({ CHAMP_DATE: { $lt: new Date(new Date().setFullYear(new Date().getFullYear() - N)) } })

------------------------------------------------------------
8. Texte qui commence par... + tri   ( 1 = croissant, -1 = décroissant )

A: db.user.find({ email: /^j/i }).sort({ birthdate: 1 })

S: db.COLLECTION.find({ CHAMP: /^TEXTE/ }).sort({ CHAMP_TRI: 1 })

------------------------------------------------------------
9. Texte, sans tenir compte des majuscules   ( le i après la regex )

A: db.user.find({ country: /France/i })

S: db.COLLECTION.find({ CHAMP: /TEXTE/i })

------------------------------------------------------------
10. Supprimer le plus ancien

A: db.user.deleteOne({ birthdate: db.user.find().sort({ birthdate: 1 }).limit(1).toArray()[0].birthdate })

S: db.COLLECTION.deleteOne({ CHAMP: db.COLLECTION.find().sort({ CHAMP: 1 }).limit(1).toArray()[0].CHAMP })

------------------------------------------------------------
11. Trouver les doublons

A: db.user.aggregate([
     { $group: { _id: "$email", count: { $sum: 1 } } },
     { $match: { count: { $gt: 1 } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: "$CHAMP", count: { $sum: 1 } } },
     { $match: { count: { $gt: 1 } } }
   ])

------------------------------------------------------------
12. Index unique   ( interdit les doublons )

A: db.user.createIndex({ email: 1 }, { unique: true })

S: db.COLLECTION.createIndex({ CHAMP: 1 }, { unique: true })

------------------------------------------------------------
13. Afficher seulement certains champs

A: db.user.find({ name: "Jane" }, { email: 1, name: 1 })

S: db.COLLECTION.find({ CHAMP: VALEUR }, { CHAMP_A_AFFICHER: 1, AUTRE_CHAMP: 1 })

------------------------------------------------------------
14. Créer une autre collection   ( 5 groupes dans l'annale )

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

A: db.user.updateOne({ name: "Jim" }, { $set: { group: "admin" } })

S: db.COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
15b. Modifier le premier selon un tri   ( ici : le plus âgé sans groupe )

A: db.user.findOneAndUpdate({ group: { $exists: false } }, { $set: { group: "secretariat" } }, { sort: { birthdate: 1 } })

S: db.COLLECTION.findOneAndUpdate({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } }, { sort: { CHAMP_TRI: 1 } })

------------------------------------------------------------
15c. Modifier tous ceux qui n'ont pas encore le champ

A: db.user.updateMany({ group: { $exists: false } }, { $set: { group: "animateur" } })

S: db.COLLECTION.updateMany({ CHAMP: { $exists: false } }, { $set: { CHAMP: VALEUR } })

------------------------------------------------------------
16. Compter avec plusieurs conditions   ( la virgule = ET )

A: db.user.countDocuments({ group: "animateur", birthdate: { $gt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) } })

S: db.COLLECTION.countDocuments({ CHAMP1: VALEUR, CHAMP2: { $gt: VALEUR } })

------------------------------------------------------------
17. Compter + nom qui commence par une lettre

A: db.user.countDocuments({ group: "animateur", birthdate: { $gt: new Date(new Date().setFullYear(new Date().getFullYear() - 25)) }, name: /^J/ })

S: db.COLLECTION.countDocuments({ CHAMP1: VALEUR, CHAMP2: { $gt: VALEUR }, CHAMP3: /^LETTRE/ })

------------------------------------------------------------
18. Âge moyen après un filtre

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

A: db.user.find({ group: "animateur" }).sort({ birthdate: 1 }).limit(2)

S: db.COLLECTION.find({ CHAMP: VALEUR }).sort({ CHAMP_TRI: 1 }).limit(N)

------------------------------------------------------------
20. Modifier plusieurs documents   ( $or = OU )

A: db.user.updateMany({ $or: [ { name: "Jil Aktem" }, { name: "Joey" } ] }, { $set: { group: "coordinator" } })

S: db.COLLECTION.updateMany({ $or: [ { CHAMP: VALEUR1 }, { CHAMP: VALEUR2 } ] }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
21. Jointure entre deux collections

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
22. Nombre et âge moyen par groupe

A: db.user.aggregate([
     { $group: { _id: "$group", count: { $sum: 1 }, averageAge: { $avg: { $divide: [ { $subtract: [new Date(), "$birthdate"] }, 1000 * 60 * 60 * 24 * 365.25 ] } } } }
   ])

S: db.COLLECTION.aggregate([
     { $group: { _id: "$CHAMP_GROUPE", count: { $sum: 1 }, NOM_MOYENNE: { $avg: "$CHAMP_NOMBRE" } } }
   ])

------------------------------------------------------------
23. Enregistrer un résultat dans une autre collection

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
25. Transaction : insérer

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
26. Transaction : modifier   ( seule la 3e ligne change )

A: session.getDatabase("TPMongo").group.updateOne({ name: "Coordinateur" }, { $set: { name: "Regulateur" } })

S: session.getDatabase("BASE").COLLECTION.updateOne({ CHAMP: VALEUR }, { $set: { CHAMP_A_MODIFIER: NOUVELLE_VALEUR } })

------------------------------------------------------------
24. Pas de réponse dans l'annale.
