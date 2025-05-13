const bcrypt = require('bcrypt');
const fs = require('fs');

async function createUser() {
  const password = 'motdepasse123';
  const hashed = await bcrypt.hash(password, 10);

  const user = {
    email: "massi@gmail.com", 
    password: hashed // Le mot de passe est haché ici
  };

  // Si le fichier existe déjà, on le lit pour ajouter un nouvel utilisateur
  let users = [];
  if (fs.existsSync('data/users.json')) {
    const data = fs.readFileSync('data/users.json', 'utf-8');
    users = JSON.parse(data);
  }

  // Ajouter le nouvel utilisateur à la liste
  users.push(user);

  // Enregistrer le fichier JSON
  fs.writeFileSync('data/users.json', JSON.stringify(users, null, 2));
  console.log("✅ Utilisateur créé avec succès !");
}

createUser();
