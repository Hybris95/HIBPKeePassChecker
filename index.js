var kpio = require('keepass.io');
var config = require('config');
var crypto = require('crypto');
var https = require('https');

var db = new kpio.Database();
var rawDatabase = null;
var basicApi = null;

var kdbxfile = config.get('KeePass.dbFile');
var kdbxpwd = config.get('KeePass.dbPassword');
var hibpHost = 'api.pwnedpasswords.com';
var hibpPath = '/range/';

db.addCredential(new kpio.Credentials.Password(kdbxpwd));
db.loadFile(kdbxfile, function(err){
	if(err) throw err;
	rawDatabase = db.getRawApi().get();
	basicApi = db.getBasicApi();
	var rootGroup = basicApi.getGroupTree()[0];
	performOnEachEntry(basicApi, rootGroup, checkEntry);
});

function performOnEachEntry(api, group, action){
	var groups = group.Groups;
	if(groups){
		for(var i = 0; i < groups.length; i++){
			performOnEachEntry(api, groups[i], action);
		}
	}
	var uuid = group.UUID;
	var entries = api.getEntries(uuid);
	if(entries){
		for(var i = 0; i < entries.length; i++){
			action(entries[i]);
		}
	}
}

function getValue(entry, key){
	var strings = entry.String;
	for(var i = 0; i < strings.length; i++){
		if(strings[i].Key == key){
			return strings[i].Value
		}
	}
}

function getPassword(entry){
	return getValue(entry, "Password")._
}

function hashString(value, type){
	return crypto.createHash(type).update(value).digest("hex");
}

function firstFive(value){
	return value.substring(0,5);
}

function showEntry(entry){
	try{
		console.log("Title: " + getValue(entry,"Title"));
		console.log("Sha1: " + hashString(getPassword(entry),"sha1"));
	}
	catch(err){
		console.log(err);
	}
	console.log("=====");
}

function checkEntry(entry){
	var title = getValue(entry,"Title");
	try{
		var password = getPassword(entry);
		var fullHash = hashString(password,"sha1");
		var cutHash = firstFive(fullHash);
		https.get({
			host: hibpHost,
			path: hibpPath + cutHash
		}, function(response){
			response.on('data', function(html){
				var hashArrays = html.toString().split("\n");
				for(var i = 0; i < hashArrays.length; i++){
					var hashSuffix = hashArrays[i].split(":")[0];
					var fullHashToCompare = cutHash + hashSuffix;
					if(fullHash == fullHashToCompare){
						console.log(title + " was found ("+fullHash+")!");
					}
				}
			});
		});
	}
	catch(err){
		console.error(err);
	}
}
