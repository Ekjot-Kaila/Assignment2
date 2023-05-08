
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const url = require('url');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 day  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

const navLinks =[
	{ name: "Home", link: "/"},
	{name: "signup", link: "/signup" },
	{ name: "login", link: "/login"},
	{name: "admin", link: "/admin/paths/paths" },
	{ name: "members", link: "/members"},
	
]
app.use("/", (req,res,next)=>{
	app.locals.navLinks = navLinks;
	app.locals.currentURL =url.parse(req.url).pathname;
    next();
});
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.get('/', (req,res) => {
    if (!req.session.authenticated) {
		return 	res.render("index");
	  }
	  var username = req.session.username;
	  res.send(
		`Hello, ${username}! <br> <a href='/members'> Go to Members Area</a> <br> <a href='/logout'> Logout</a> `
	  );  
	


});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.render("about", {color: color});
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;

    res.render("contact", {missing: missingEmail});
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});


app.get('/signup', (req,res) => {
	var missingUsername = req.query.missing;
	var missingEmail = req.query.missings;
	var missingPassword = req.query.missingss;
	var emailandpassword = req.query.ep;
	var emailandusername = req.query.eu;
	var usernameandpassword = req.query.up;
	var emailandusernameandpassword = req.query.eup;
	
	  res.render("createUser",{missing: missingUsername, missings: missingEmail, missingss: missingPassword, ep: emailandpassword, eu: emailandusername, up: usernameandpassword, eup:emailandusernameandpassword });
	});


app.get('/login', (req,res) => {
	var missingUsername = req.query.missing;
	
	  res.render("login", {missing: missingUsername});
});

app.post('/submitUser', async (req,res) => {
	var email = req.body.email;
	var username = req.body.username;
	var password = req.body.password;
	if (!password && !username && !email) {
	  return res.redirect("/signup?eup=1");
	}
	if (!email && !password) {
	  return res.redirect("/signup?ep=1");
	}
	if (!username && !email) {
	  return res.redirect("/signup?eu=1");
	}
	if (!password && !username) {
	  return res.redirect("/signup?up=1");
	}
	if (!username) {
	  return res.redirect("/signup?missing=1");
	}
	if (!email) {
	  return res.redirect("/signup?missings=1");
	}
	if (!password) {
	  return res.redirect("/signup?missingss=1");
	} else {
	  const schema = Joi.object({
		username: Joi.string().alphanum().max(20).required(),
		password: Joi.string().max(20).required(),
		email: Joi.string().email().required(),
	  });
  
	  const validationResult = schema.validate({ username, password, email });
	  if (validationResult.error != null) {
		console.log(validationResult.error);
		res.redirect("/signup");
		return; 
	  }
  
	  var hashedPassword = await bcrypt.hash(password, saltRounds);
  
	  await userCollection.insertOne({
		username: username,
		email: email,
		password: hashedPassword,
	  });
	  console.log("Inserted user");
	  req.session.authenticated = true;
	  req.session.username = username;
	  
	  var html = "successfully created user";
	 // res.send(html);
	 return res.redirect("/members") 
	}
});

app.post('/loggingin', async (req,res) => {
   // var username = req.body.username;
   var password = req.body.password;
   var email = req.body.email;
   const schema = Joi.string().max(20).required();
   const validationResult = schema.validate(email);
   if (validationResult.error != null) {
	 console.log(validationResult.error);
	 res.redirect("/login");
	 return;
   }
 
   const result = await userCollection
	 .find({ email: email })
	 .project({ email: 1, password: 1, username:1, user_type: 1, _id: 1 })
	 .toArray();
 
   
	 
   console.log(result);
   if (result.length != 1) {
	 console.log("user not found");
	 res.redirect("/login?missing=1");
	 return;
   }
   if (await bcrypt.compare(password, result[0].password)) {
	 console.log("correct password");
	 req.session.authenticated = true;
	 req.session.username = result[0].username;
	 req.session.cookie.maxAge = expireTime;
	 req.session.user_type = result[0].user_type;
	 req.session.cookie.maxAge = expireTime;
	 res.redirect("/members");
	 
   } else {
	 console.log("incorrect password");
	 res.redirect("/login?missing=1");
	 return;
   }
});

app.use('/members', sessionValidation);
app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
	var username = req.session.username;
	res.render("loggedin", {username: username});
});

app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});

app.get('/logout', (req,res) => {
	req.session.destroy();
    res.render("loggedout");
});


app.get('/cat/:id', (req,res) => {
    var cat = req.params.id;

    res.render("cat", {cat: cat});
});


app.get('/admin/:id/:changes', sessionValidation, adminAuthorization, async (req,res) => {
    var changes = req.params.changes
	var change = req.params.id;
	console.log(change)
	const result = await userCollection.find().project({username: 1, _id: 1, user_type:1}).toArray();
   if(changes==2){ 
    await userCollection.updateOne({username: change}, {$set: {user_type: 'user'}})
	return res.render("admin", {users: result});
}
	if(changes==1){ 
		await userCollection.updateOne({username: change}, {$set: {user_type: 'admin'}})
	return	res.render("admin", {users: result});
	    
}
	return res.render("admin", {users: result});
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 