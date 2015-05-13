// requires the use of a client side fake cookie session adapter
// ie my angular adapter

var BSON = require('buffalo');
var crypto = require('crypto');
var xor = require('bitwise-xor');

var hmac = crypto.createHmac("sha256", 'thisisthebigcrappytokenthing'); 
var hash2 = hmac.update('thisisanotherbigcrappytokenthing');
var mask = hmac.digest('hex');

module.exports = function(req, res, next){
    if(req.body.cookie === 'undefined') req.body.cookie = undefined;

    // this should parse and check the prepended signature

    var pxbuffer = new Buffer(req.body.cookie||'V0dS3HI=', 'base64');

    var longmask = mask;
    while(longmask.length < 2*(pxbuffer||'').length) longmask += mask;

    var pbuffer = xor(pxbuffer, new Buffer(longmask, 'hex'));
    var outbson = BSON.parse(pbuffer);

    req.session = outbson;

    var resjson = res.json;
    res.json = function(jj){
	// crypto the cookie and send it in the res.fakeCookie

	// this should prepend a signature

	var buffer = BSON.serialize(req.session||{});

	var longmask = mask;
	while(longmask.length < 2*buffer.length) longmask += mask;

	var xbuffer = xor(buffer, new Buffer(longmask, 'hex'));
	var b64 = xbuffer.toString('base64');

	if(req.method === 'POST') jj.fakeCookie = b64;

	return resjson.apply(res, arguments);
    };

    next();
};
