/*
	TokyoTyrant.js
	author: Masatoshi Teruya
	email: mah0x211@gmail.com
	copyright (C) 2011, masatoshi teruya. all rights reserved.
*/
var package = {
	util: require('util'),
	net: require('net'),
	events: require('events'),
	BufferIO: require('BufferIO'),
	ctype: require('ctype')
};


// MARK: TYPE CHECKER
function isNumber( arg ){
	return ( typeof arg === 'number' );
}
function isString( arg ){
	return ( typeof arg === 'string' );
}
function isArray( arg ){
	return ( arg && arg.constructor === Array );
}
function isObject( arg ){
	return ( arg && arg.constructor === Object );
}
function isTyrant( arg ){
	return ( arg && 
		   ( arg.constructor === module.exports.Table || 
		     arg.constructor === module.exports.Hash ) );
}


var _BIGENDIAN = ( parseInt( "0x00000001" ) === 1 ),
	_QUADBASE = Math.pow( 2, 32 ),
	_TRILLIONNUM = 10000000000,
	// MARK: status
	ESUCCESS = 0,
	EINVALID = 1,
	ENOHOST = 2,
	// refuse
	EREFUSED = 3,
	ESEND = 4,
	ERECV = 5,
	EKEEP = 6,
	ENOREC = 7,
	EMISC = 9999,
	// MARK: options
	OPTS = {
		// tuning options
		// reconnect automatically
		TRECON: 1 << 0,
		// scripting extension options
		// record locking
		XOLCKREC: 1 << 0,
		// global locking
		XOLCKGLB: 1 << 1,
		// restore options
		// consistency checking
		ROCHKCON: 1 << 0,
		// miscellaneous operation options
		// omission of update log
		MONOULOG: 1 << 0,
		
		// Table options
		// enumeration for index types
		// lexical string
		ITLEXICAL: 0,
		// decimal string
		ITDECIMAL: 1,
		// token inverted index
		ITTOKEN: 2,
		// q-gram inverted index
		ITQGRAM: 3,
		// optimize
		ITOPT: 9998,
		// void
		ITVOID: 9999,
		// keep existing index
		ITKEEP: 1 << 24
	};

// MARK: PROTOCOLS
function Protocol(){}
/* MARK: tmpl_k_kb
Request: [magic:2][ksiz:4][kbuf:*]
	Two bytes of the command ID: 0xC8 and cmd
	A 32-bit integer standing for the length of the key
	Arbitrary data of the key
*/
Protocol.tmpl_k_kb = function( cmd, key )
{
	var buf = undefined;
	
	if( isNumber( cmd ) && isString( key ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of the command ID: 0xC8 and cmd
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( cmd );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [kbuf:*] Arbitrary data of the key
		bio.write.string( key );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

/* MARK: tmpl_kv_kbvb
Request: [magic:2][ksiz:4][vsiz:4][kbuf:*][vbuf:*]
	Two bytes of magic[0xC8] + the command ID
	A 32-bit integer standing for the length of the key
	A 32-bit integer standing for the length of the value
	Arbitrary data of the key
	Arbitrary data of the value
*/
Protocol.tmpl_kv_kbvb = function( cmd, key, val )
{
	var buf = undefined;
	
	if( isNumber( cmd ) && isString( key ) && isString( val ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of magic[0xC8] + the cmd
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( cmd );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [vsiz:4] A 32-bit integer standing for the length of the value
		bio.write.uint32_t( Buffer.byteLength( val ) );
		// [kbuf:*] Arbitrary data of the key
		bio.write.string( key );
		// [vbuf:*] Arbitrary data of the value
		bio.write.string( val );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

/* MARK: tmpl_k32_kb
Request: [magic:2][ksiz:4][i32:4][kbuf:*]
	Two bytes of the command ID: 0xC8 and cmd
	A 32-bit integer standing for the length of the key
	A 32-bit integer standing for the maximum number of keys to be fetched
	Arbitrary data of the prefix
*/
Protocol.tmpl_k32_kb = function( cmd, key, i32 )
{
	// param error
	var buf = undefined;
	
	if( isNumber( cmd ) && isString( key ) && isNumber( i32 ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of the command ID: 0xC8 and cmd
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( cmd );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [i32:4] A 32-bit integer standing for the maximum number of keys to be fetched
		bio.write.uint32_t( i32 );
		// [kbuf:*] Arbitrary data of the prefix
		bio.write.string( key );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

// MARK: put
Protocol.put = function( key, val ){
	return this.tmpl_kv_kbvb( 0x10, key, val );
};
// MARK: putkeep
Protocol.putkeep = function( key, val ){
	return this.tmpl_kv_kbvb( 0x11, key, val );
};
// MARK: putcat
Protocol.putcat = function( key, val ){
	return this.tmpl_kv_kbvb( 0x12, key, val );
};

/* MARK: putshl
Request: [magic:2][ksiz:4][vsiz:4][width:4][kbuf:*][vbuf:*]
	Two bytes of the command ID: 0xC8 and 0x13
	A 32-bit integer standing for the length of the key
	A 32-bit integer standing for the length of the value
	A 32-bit integer standing for the width
	Arbitrary data of the key
	Arbitrary data of the value
*/
Protocol.putshl = function( key, val, width )
{
	var buf = undefined;
	
	if( isString( key ) && isString( val ) && isNumber( width ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of the command ID: 0xC8 and 0x13
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x13 );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [vsiz:4] A 32-bit integer standing for the length of the value
		bio.write.uint32_t( Buffer.byteLength( val ) );
		// [width:4] A 32-bit integer standing for the width
		bio.write.uint32_t( ( width < 0 ) ? 0 : width );
		// [kbuf:*] Arbitrary data of the key
		bio.write.string( key );
		// [vbuf:*] Arbitrary data of the value
		bio.write.string( val );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

// MARK: putnr
Protocol.putnr = function( key, val ){
	return this.tmpl_kv_kbvb( 0x18, key, val );
};

// MARK: out
Protocol.out = function( key ){
	return this.tmpl_k_kb( 0x20, key );
};

// MARK: get
Protocol.get = function( key ){
	return this.tmpl_k_kb( 0x30, key );
};

/* MARK: mget
Request: [magic:2][rnum:4][{[ksiz:4][kbuf:*]}:*]
	magic: Two bytes of the command ID: 0xC8 and 0x31
	rnum: A 32-bit integer standing for the number of keys
	iteration:
		ksiz: A 32-bit integer standing for the length of the key
		kbuf: Arbitrary data of the key
*/
Protocol.mget = function( keys )
{
	// param error
	var buf = undefined;
	
	if( isArray( keys ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } ),
			key;
		
		// [magic:2] magic: Two bytes of the command ID: 0xC8 and 0x31
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x31 );
		// [rnum:4] rnum: A 32-bit integer standing for the number of keys
		bio.write.uint32_t( keys.length );
		// [{[ksiz:4][kbuf:*]}:*] iteration:
		while( ( key = keys.shift() ) ){
			// [ksiz:4] ksiz: A 32-bit integer standing for the length of the key
			bio.write.uint32_t( Buffer.byteLength( key ) );
			// [kbuf:*] kbuf: Arbitrary data of the key
			bio.write.string( key );
		}
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

// MARK: vsiz
Protocol.vsiz = function( key ){
	return this.tmpl_k_kb( 0x38, key );
};

// MARK: iterinit
Protocol.iterinit = function(){
	return new Buffer( [0xC8,0x50] );
};
// MARK: iternext
Protocol.iternext = function(){
	return new Buffer( [0xC8,0x51] );
};


/* MARK: fwmkeys
Request: [magic:2][psiz:4][max:4][pbuf:*]
	Two bytes of the command ID: 0xC8 and 0x58
	A 32-bit integer standing for the length of the prefix
	A 32-bit integer standing for the maximum number of keys to be fetched
	Arbitrary data of the prefix
*/
Protocol.fwmkeys = function( prefix, max )
{
	return this.tmpl_k32_kb( 0x58, prefix, ( max < 0 ) ? 1 << 31 : max );
};

/* MARK: addint
Request: [magic:2][ksiz:4][num:4][kbuf:*]
	Two bytes of the command ID: 0xC8 and 0x60
	A 32-bit integer standing for the length of the key
	A 32-bit integer standing for the additional number
	Arbitrary data of the key
*/
Protocol.addint = function( key, num )
{
	return this.tmpl_k32_kb( 0x60, key, num );
};

/* MARK: adddouble
Request: [magic:2][ksiz:4][integ:8][fract:8][kbuf:*]
	Two bytes of the command ID: 0xC8 and 0x61
	A 32-bit integer standing for the length of the key
	A 64-bit integer standing for the integral of the additional number
	A 64-bit integer standing for the trillionfold fractional of the additional number
	Arbitrary data of the key
*/
Protocol.adddouble = function( key, num )
{
	// param error
	var buf = undefined;
	
	if( isString( key ) && isNumber( num ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		num = num.toString().split('.', 2 );
		num[0] = parseInt( num[0] );
		num[1] = ( num[1] ) ? parseInt( num[1] ) : 0;
		num[1] *= _TRILLIONNUM;
		// [magic:2] Two bytes of the command ID: 0xC8 and 0x61
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x61 );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [integ:8] A 64-bit integer standing for the integral of the additional number
		bio.write.uint32_t( ~~( num[0] / _QUADBASE ) );
		bio.write.uint32_t( num[0] % _QUADBASE );
		// [fract:8] A 64-bit integer standing for the trillionfold fractional of the additional number
		bio.write.uint32_t( ~~( num[1] / _QUADBASE ) );
		bio.write.uint32_t( num[1] % _QUADBASE );
		// [kbuf:*] Arbitrary data of the key
		bio.write.string( key );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

/* MARK: ext
Request: [magic:2][nsiz:4][opts:4][ksiz:4][vsiz:4][nbuf:*][kbuf:*][vbuf:*]
	Two bytes of the command ID: 0xC8 and 0x68
	A 32-bit integer standing for the length of the function name
	A 32-bit integer standing for the options
	A 32-bit integer standing for the length of the key
	A 32-bit integer standing for the length of the value
	Arbitrary data of the function name
	Arbitrary data of the key
	Arbitrary data of the value
*/
Protocol.ext = function( name, opts, key, val )
{
	// param error
	var buf = undefined;
	
	if( isString( name ) && isString( key ) && isNumber( opts ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );

		// [magic:2] Two bytes of the command ID: 0xC8 and 0x68
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x68 );
		// [nsiz:4] A 32-bit integer standing for the length of the function name
		bio.write.uint32_t( Buffer.byteLength( name ) );
		// [opts:4] A 32-bit integer standing for the options
		bio.write.uint32_t( opts );
		// [ksiz:4] A 32-bit integer standing for the length of the key
		bio.write.uint32_t( Buffer.byteLength( key ) );
		// [vsiz:4] A 32-bit integer standing for the length of the value
		bio.write.uint32_t( Buffer.byteLength( val ) );
		// [nbuf:*] Arbitrary data of the function name
		bio.write.string( name );
		// [kbuf:*] Arbitrary data of the key
		bio.write.string( key );
		// [vbuf:*] Arbitrary data of the value
		bio.write.string( val );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

// MARK: sync
Protocol.sync = function(){
	return new Buffer( [0xC8,0x70] );
};
// MARK: optimize
Protocol.optimize = function( param ){
	return this.tmpl_k_kb( 0x71, param );
};
// MARK: vanish
Protocol.vanish = function(){
	return new Buffer( [0xC8,0x72] );
};

// MARK: copy
Protocol.copy = function( param ){
	return this.tmpl_k_kb( 0x73, param );
};

/* MARK: restore
Request: [magic:2][psiz:4][ts:8][opts:4][pbuf:*]
	Two bytes of the command ID: 0xC8 and 0x74
	A 32-bit integer standing for the length of the path
	A 64-bit integer standing for the beginning time stamp in microseconds
	A 32-bit integer standing for the options
	Arbitrary data of the path
*/
Protocol.restore = function( path, ts, opts )
{
	// param error
	var buf = undefined;
	
	if( isString( path ) && isNumber( ts ) && isNumber( opts ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of the command ID: 0xC8 and 0x74
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x74 );
		// [psiz:4] A 32-bit integer standing for the length of the path
		bio.write.uint32_t( Buffer.byteLength( path ) );
		// [ts:8] A 64-bit integer standing for the beginning time stamp in microseconds
		bio.write.uint32_t( ~~( ts / _QUADBASE ) );
		bio.write.uint32_t( ts % _QUADBASE );
		// [opts:4] A 32-bit integer standing for the options
		bio.write.uint32_t( opts );
		// [pbuf:*] Arbitrary data of the path
		bio.write.string( path );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};


/* MARK: setmst
Request: [magic:2][hsiz:4][port:4][ts:8][opts:4][host:*]
	Two bytes of the command ID: 0xC8 and 0x78
	A 32-bit integer standing for the length of the host name
	A 32-bit integer standing for the port number
	A 64-bit integer standing for the beginning time stamp in microseconds
	A 32-bit integer standing for the options
	Arbitrary data of the host name
*/
Protocol.setmst = function( host, port, ts, opts )
{
	// param error
	var buf = undefined;
	
	if( isString( host ) && isNumber( port ) && isNumber( ts ) && isNumber( opts ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } );
		
		// [magic:2] Two bytes of the command ID: 0xC8 and 0x78
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x78 );
		// [hsiz:4] A 32-bit integer standing for the length of the host name
		bio.write.uint32_t( Buffer.byteLength( host ) );
		// [port:4] A 32-bit integer standing for the port number
		bio.write.uint32_t( port );
		// [ts:8] A 64-bit integer standing for the beginning time stamp in microseconds
		bio.write.uint32_t( ~~( ts / _QUADBASE ) );
		bio.write.uint32_t( ts % _QUADBASE );
		// [opts:4] A 32-bit integer standing for the options
		bio.write.uint32_t( opts );
		// [host:*] Arbitrary data of the host name
		bio.write.string( host );

		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
	}
	
	return buf;
};

// MARK: rnum
Protocol.rnum = function(){
	return new Buffer( [0xC8,0x80] );
};
// MARK: size
Protocol.size = function(){
	return new Buffer( [0xC8,0x81] );
};
// MARK: stat
Protocol.stat = function(){
	return new Buffer( [0xC8,0x88] );
};

/* MARK: misc
Request: [magic:2][nsiz:4][opts:4][rnum:4][nbuf:*] [{[asiz:4][abuf:*]}:*]
	magic: Two bytes of the command ID: 0xC8 and 0x90
	nsiz: A 32-bit integer standing for the length of the function name
	opts: A 32-bit integer standing for the options
	rnum: A 32-bit integer standing for the number of arguments
	nbuf: Arbitrary data of the function name
	iteration:
		asiz: iteration: A 32-bit integer standing for the length of the argument
		abuf: iteration: Arbitrary data of the argument
*/
Protocol.misc = function( cmd, opts, args )
{
	// param error
	var buf = undefined;
	
	if( isString( cmd ) && isNumber( opts ) && isArray( args ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } ),
			rnum = args.length,
			args_t = {
				total: 0,
				siz: [],
				// true == Buffer
				isBuffer: []
			},
			arg;
		
		// calculate arguments size
		for( var i = 0; i < rnum; i++ )
		{
			if( Buffer.isBuffer( args[i] ) ){
				args_t.isBuffer[i] = true;
				args_t.siz[i] = args[i].length;
			}
			else
			{
				if( isNumber( args[i] ) ){
					args[i] = args[i].toString();
				}
				args_t.isBuffer[i] = false;
				args_t.siz[i] = Buffer.byteLength( args[i] );
			}
			args_t.total += args_t.siz[i];
		}
		
		if( opts < 0 ){
			opts = 0;
		}
		// [magic:2] Two bytes of the command ID: 0xC8 and 0x90
		bio.write.uint8_t( 0xC8 );
		bio.write.uint8_t( 0x90 );
		// [nsiz:4] A 32-bit integer standing for the length of the function name
		bio.write.uint32_t( Buffer.byteLength( cmd ) );
		// [opts:4] A 32-bit integer standing for the options
		bio.write.uint32_t( opts );
		// [rnum:4] A 32-bit integer standing for the number of arguments
		bio.write.uint32_t( rnum );
		// [nbuf:*] Arbitrary data of the function name
		bio.write.string( cmd );
		// [{[asiz:4][abuf:*]} iteration
		for( var i = 0; i < rnum; i++ )
		{
			// [asiz:4] A 32-bit integer standing for the length of the argument
			bio.write.uint32_t( args_t.siz[i] );
			// [abuf:*] Arbitrary data of the argument
			if( args_t.isBuffer[i] ){
				bio.write.buffer( args[i] );
			}
			else {
				bio.write.string( args[i] );
			}
		}
		
		// create buffer
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
		delete bio;
	}
	/* !!!: may be its bug of node.js or v8 engine if display bio
	console.log( 'bio:' + bio.buf );
	*/
	
	return buf;
};

Protocol.recv = function( protocol, cmd, buf )
{
	var bio = new package.BufferIO( { endian: 'big' }, buf ),
		data = {};
	
	switch( protocol )
	{
		case 'put':
		case 'putkeep':
		case 'putcat':
		case 'putshl':
		case 'out':
		case 'iterinit':
		case 'sync':
		case 'optimize':
		case 'vanish':
		case 'copy':
		case 'restore':
		case 'setmst':
		/* Response: [code:1]
			An 8-bit integer whose value is 0 on success or another on failure */
			data.code = bio.read.int8_t();
		break;
		case 'rnum':
		case 'size':
		/* Response: [code:1][size:8]
			[code:1]
				An 8-bit integer whose value is always 0
			[size:8]
				rnum: A 64-bit integer standing for the number of records
				size: A 64-bit integer standing for the size of the database */
			data.code = bio.read.int8_t();
			data.high = bio.read.int32_t();
			data.low = bio.read.int32_t();
			data[cmd] = ( data.high << 32 ) + data.low;
		break;
		case 'vsiz':
		case 'addint':
		/* Response: [code:1]([size:4])
			[code:1]
				An 8-bit integer whose value is 0 on success or another on failure
			[size:4]
				vsiz: on success: A 32-bit integer standing for the length of the value
				addint: on success: A 32-bit integer standing for the summation value */
			data.code = bio.read.int8_t();
			if( data.code === 0 ){
				data[cmd] = bio.read.int32_t();
			}
		break;
		case 'adddouble':
		/* Response: [code:1]([integ:8][fract:8])
			[code:1]
				An 8-bit integer whose value is 0 on success or another on failure
			[integ:8]
				on success: A 64-bit integer standing for the integral of the summation value
			[fract:8]
				on success: A 64-bit integer standing for the trillionfold fractional of the summation value */
			data.code = bio.read.int8_t();
			if( data.code === 0 ){
				data.integral = bio.read.int32_t() * _QUADBASE + bio.read.int32_t(),
				data.fractional = bio.read.int32_t() * _QUADBASE + bio.read.int32_t();
				data[cmd] = parseFloat( data.integral + '.' + data.fractional );
			}
		break;
		case 'get':
		case 'iternext':
		case 'ext':
		case 'stat':
		/* Response: [code:1]([size:4][vbuf:*])
			[code:1]
				get,iternext,ext: An 8-bit integer whose value is 0 on success or another on failure
				stat: An 8-bit integer whose value is always 0
			[size:4]
				get: on success: A 32-bit integer standing for the length of the value
				iternext: on success: A 32-bit integer standing for the length of the key
				ext: on success: A 32-bit integer standing for the length of the result
				stat: A 32-bit integer standing for the length of the status message
			[vbuf:*]
				get: on success: Arbitrary data of the value
				iternext: on success: Arbitrary data of the key
				ext: on success: Arbitrary data of the result
				stat: Arbitrary data of the result */
			data.code = bio.read.int8_t();
			if( data.code === 0 ){
				data.length = bio.read.int32_t();
				data[cmd] = bio.read.string( data.size );
			}
		break;
		case 'mget':
		/*Response: [code:1][rnum:4][{[ksiz:4][vsiz:4][kbuf:*][vbuf:*]}:*]
			An 8-bit integer whose value is 0 on success or another on failure
			A 32-bit integer standing for the number of records
			iteration: A 32-bit integer standing for the length of the key
			iteration: A 32-bit integer standing for the length of the value
			iteration: Arbitrary data of the key
			iteration: Arbitrary data of the value */
			data.code = bio.read.int8_t();
			if( data.code === 0 )
			{
				data.length = bio.read.int32_t();
				if( data.length )
				{
					var rows = [];
					
					for( var i = 0; i < data.length; i++ )
					{
						var ksiz = bio.read.int32_t(),
							vsiz = bio.read.int32_t(),
							col = {},
							key,val;
						
						key = bio.read.string( ksiz );
						val = bio.read.string( vsiz );
						col[key] = ( val ) ? val.split( "\u0000" ) : '';
						rows.push( col );
					}
					data[cmd] = rows;
				}
			}
		break;
		case 'fwmkeys':
		case 'misc':
		case 'setindex':
		case 'genuid':
		/* Response: [code:1][num:4][{[siz:4][buf:*]}:*]
			[code:1]
				fwmkeys,misc,genuid : An 8-bit integer whose value is 0 on success or another on failure
				setindex: If successful, the return value is true, else, it is false
			[num:4]
				fwmkeys: A 32-bit integer standing for the number of keys
				misc: A 32-bit integer standing for the number of result elements
				genuid: The return value is the new unique ID number or -1 on failure
			[siz:4]
				fwmkeys: iteration: A 32-bit integer standing for the length of the key
				misc: iteration: A 32-bit integer standing for the length of the element
			[buf:*]
				fwmkeys: iteration: Arbitrary data of the key
				misc: iteration: Arbitrary data of the element */
			var hint = /^\0\0\[\[HINT]]\n/;
			
			data.code = bio.read.int8_t();
			if( data.code === 0 )
			{
				var length = bio.read.int32_t();
				
				if( length )
				{
					var rows = [];
					
					data.length = length;
					for( var i = 0; i < length; i++ ){
						var siz = bio.read.int32_t();
						rows.push( bio.read.string( siz ) );
					}
					// check hint
					if( ( hint = hint.exec( rows[length-1] ) ) ){
						data.hint = rows.pop().replace( hint[0], "[[HINT]]\n" );
						data.length--;
					}
					if( cmd === 'genuid' ){
						data[cmd] = rows.shift();
						delete data.length;
					}
					else {
						data[cmd] = rows;
					}
				}
			}
		break;

	};
	
	return data;
};

// MARK: BASE
function TokyoTyrant(){}
// properties
TokyoTyrant.prototype = {
	_evt: new package.events.EventEmitter,
	_ecode: 0,
	_sock: undefined,
	_tout: undefined,
	_task: [],
	_progress: false,
	opt:{}
};
// add options
for( var o in OPTS ){
	TokyoTyrant.prototype.opt[o] = OPTS[o];
}

// int tcrdbecode(TCRDB *rdb);
TokyoTyrant.prototype.ecode = function()
{
	return this._ecode;
};
// const char *tcrdberrmsg(int ecode);
TokyoTyrant.prototype.errmsg = function()
{
	var ecode = arguments[0],
		msg = "unknown";
	
	if( !arguments.length ){
		ecode = this._ecode;
	}
	
	switch( ecode )
	{
		case ESUCCESS:
			msg = "success";
		break;
		case EINVALID:
			msg = "invalid operation";
		break;
		case ENOHOST:
			msg = "host not found";
		break;
		case EREFUSED:
			msg = "connection refused";
		break;
		case ESEND:
			msg = "send error";
		break;
		case ERECV:
			msg = "recv error";
		break;
		case EKEEP:
			msg = "existing record";
		break;
		case ENOREC:
			msg = "no record found";
		break;
		case EMISC:
			msg = "miscellaneous error";
		break;
	};
	
	return msg;
};

TokyoTyrant.prototype.open = function( host, port, timeout, pass )
{
	if( !isString( host ) || !host.length ){
		throw Error( 'failed to open: invalid parameter' );
	}
	else if( !this._sock )
	{
		var self = this,
			type = 'unix';
		
		if( isNumber( port ) && port > 0 ){
			type = ( package.net.isIPv6( host ) ) ? 'tcp6' : 'tcp4';
		}
		
		// set timeout
		this._tout = ( isNumber( timeout ) && timeout > 0 ) ? timeout : 0;
		// create sock by tcp
		this._sock = new package.net.Socket({
			fd: null,
			type: type,
			allowHalfOpen: false
		});
		// setup
		// on connect
		this._sock.on( 'connect', function(){
			// set no delay
			self._sock.setNoDelay( true );
			self._evt.emit( 'connect' );
		} );
		// on end
		this._sock.on( 'end', function(){
			self._evt.emit( 'end' );
		} );
		// on timeout
		this._sock.on( 'timeout', function(){
			self._evt.emit( 'timeout' );
		} );
		// on drain
		this._sock.on( 'drain', function(){
			self._evt.emit( 'drain' );
		} );
		// on error
		this._sock.on( 'error', function( excep ){
			self._ecode = EREFUSED;
			self._evt.emit( 'error', excep );
		} );
		// on close
		this._sock.on( 'close', function( had_error ){
			delete self._sock;
			self._evt.emit( 'close', had_error );
		} );
		// connect
		this._sock.connect( port, host );
	}
	
	return ESUCCESS;
};

TokyoTyrant.prototype.close = function()
{
	if( !this._sock ){
		this._ecode = EINVALID;
		return EINVALID;
	}
	this._sock.end();
	this._sock.once( 'error', function( excep ){
		self._ecode = EMISC;
		self._evt.emit( 'error', excep );
	} );
	
	return ESUCCESS;
};

// bool tcrdbtune(TCRDB *rdb, double timeout, int opts);
// TokyoTyrant.prototype.tune = function( timeout, opts ){};

TokyoTyrant.prototype.on = function()
{
	this._evt.on( arguments[0], arguments[1] );
};

TokyoTyrant.prototype.invoke = function()
{
	var rc = ESUCCESS,
		task;
	
	if( !this._sock ){
		rc = this._ecode = EINVALID;
	}
	else if( !this._progress && ( task = this._task.shift() ) )
	{
		var self = this;
		
		this._progress = true;
		this._sock.write( task.buf, 'binary', function()
		{
			if( task.cmd !== 'putnr' )
			{
				self._sock.once( 'data', function( data )
				{
					task.result = Protocol.recv( task.protocol, task.cmd, data );
					task.result.buf = data;
					self._evt.emit( 'data', task );
					self._progress = false;
					self.invoke();
				} );
			}
			else {
				self._evt.emit( 'data', task.cmd );
				self._progress = false;
				self.invoke();
			}
		} );
	}
	
	return rc;
};


// MARK: RDBQRY
function Qry()
{
	this.cond = [new Buffer('hint')];
	
	// enumeration for query conditions
	this.opt = {
		// string is equal to 
		QCSTREQ: 0,
		// string is included in 
		QCSTRINC: 1,
		// string begins with 
		QCSTRBW: 2,
		// string ends with 
		QCSTREW: 3,
		// string includes all tokens in 
		QCSTRAND: 4,
		// string includes at least one token in 
		QCSTROR: 5,
		// string is equal to at least one token in 
		QCSTROREQ: 6,
		// string matches regular expressions of 
		QCSTRRX: 7,
		// number is equal to 
		QCNUMEQ: 8,
		// number is greater than 
		QCNUMGT: 9,
		// number is greater than or equal to 
		QCNUMGE: 10,
		// number is less than 
		QCNUMLT: 11,
		// number is less than or equal to 
		QCNUMLE: 12,
		// number is between two tokens of 
		QCNUMBT: 13,
		// number is equal to at least one token in 
		QCNUMOREQ: 14,
		// full-text search with the phrase of 
		QCFTSPH: 15,
		// full-text search with all tokens in 
		QCFTSAND: 16,
		// full-text search with at least one token in 
		QCFTSOR: 17,
		// full-text search with the compound expression of 
		QCFTSEX: 18,
		// negation flag 
		QCNEGATE: 1 << 24,
		// no index flag 
		QCNOIDX: 1 << 25,

		// enumeration for order types
		// string ascending 
		QOSTRASC: 0,
		// string descending 
		QOSTRDESC: 1,
		// number ascending 
		QONUMASC: 2,
		// number descending 
		QONUMDESC: 3,

		// enumeration for set operation types
		// union 
		MSUNION: 0,
		// intersection 
		MSISECT: 1,
		// difference 
		MSDIFF: 2
	};
};
// package.util.inherits( Qry, package.events.EventEmitter );

// void tcrdbqryaddcond(RDBQRY *qry, const char *name, int op, const char *expr);
Qry.prototype.addcond = function( name, op, expr )
{
	// error
	if( !isString( name ) || !isNumber( op ) || !isString( expr ) ){
		throw new Error( 'failed to addcond: invalid parameter' );
	}
	else
	{
		var bio = new package.BufferIO( { endian: 'big' } ),
			buf;
		
		// [cmd]
		bio.write.string( 'addcond' );
		// [NULL]
		bio.write.int8_t( 0x00 );
		// [name]
		bio.write.string( name );
		// [NULL]
		bio.write.int8_t( 0x00 );
		// [op:int32]
		bio.write.string( ''+op );
		// [NULL]
		bio.write.int8_t( 0x00 );
		// [expr]
		bio.write.string( expr );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
		this.cond.push( buf );
	}
	
	return this;
};

// void tcrdbqrysetorder(RDBQRY *qry, const char *name, int type);
Qry.prototype.setorder = function( name, type )
{
	// error
	if( !isString( name ) ){
		throw new Error( 'failed to setorder: invalid parameter' );
	}
	else
	{
		var bio = new package.BufferIO( { endian: 'big' } ),
			buf;

		if( !isNumber( type ) ){
			type = this.opt.QOSTRASC;
		}

		// [cmd]
		bio.write.string( 'setorder' );
		// [NULL]
		bio.write.int8_t( 0x00 );
		// [name]
		bio.write.string( name );
		// [NULL]
		bio.write.int8_t( 0x00 );
		// [type:int32]
		bio.write.string( ''+type );
		
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
		this.cond.push( buf );
	}
	
	return this;
};

// void tcrdbqrysetlimit(RDBQRY *qry, int max, int skip);
Qry.prototype.setlimit = function( max, skip )
{
	var bio = new package.BufferIO( { endian: 'big' } ),
		buf;

	if( !isNumber( max ) ){
		max = -1;
	}
	if( !isNumber( skip ) ){
		skip = -1;
	}
	
	// [cmd]
	bio.write.string( 'setlimit' );
	// [NULL]
	bio.write.int8_t( 0x00 );
	// [max:int32]
	bio.write.string( ''+max );
	// [NULL]
	bio.write.int8_t( 0x00 );
	// [skip:int32]
	bio.write.string( ''+skip );
	
	buf = new Buffer( bio.size );
	bio.buf.copy( buf );
	this.cond.push( buf );
	
	return this;
};

// TCLIST *tcrdbqrysearch(RDBQRY *qry);
Qry.prototype.search = function( tyrant )
{
	if( !isTyrant( tyrant ) ){
		throw new Error( 'failed to search: invalid parameter' );
	}
	return tyrant.misc( 'search', OPTS.MONOULOG, this.cond );
};

// bool tcrdbqrysearchout(RDBQRY *qry);
Qry.prototype.searchout = function( tyrant )
{
	if( !isTyrant( tyrant ) ){
		throw new Error( 'failed to searchout: invalid parameter' );
	}
	this.cond.push( new Buffer( 'out' ) );
	return tyrant.misc( 'search', 0, this.cond );
};

// TCLIST *tcrdbqrysearchget(RDBQRY *qry);
// TCMAP *tcrdbqryrescols(TCLIST *res, int index);
Qry.prototype.searchget = function( tyrant, name )
{
	if( !isTyrant( tyrant ) ){
		throw new Error( 'failed to searchget: invalid parameter' );
	}
	
	if( isArray( name ) )
	{
		var bio = new package.BufferIO( { endian: 'big' } ),
			nsiz = name.length,
			buf;
		
		// [cmd]
		bio.write.string( 'get' );
		// [NULL]
		bio.write.uint8_t( 0x00 );
		// [name][NULL]
		for( var i = 0; i < nsiz; i++ ){
			bio.write.string( name[i] );
			bio.write.uint8_t( 0x00 );
		}
		
		bio.size = bio.size - 1;
		buf = new Buffer( bio.size );
		bio.buf.copy( buf );
		this.cond.push( buf );
	}
	else {
		this.cond.push( new Buffer( 'get' ) );
	}
	
	return tyrant.misc( 'search', OPTS.MONOULOG, this.cond );
};

// int tcrdbqrysearchcount(RDBQRY *qry);
Qry.prototype.searchcount = function( tyrant )
{
	if( !isTyrant( tyrant ) ){
		throw new Error( 'failed to searchcount: invalid parameter' );
	}
	this.cond.push( new Buffer( 'count' ) );
	return tyrant.misc( 'search', OPTS.MONOULOG, this.cond );
};

// const char *tcrdbqryhint(RDBQRY *qry);

// TCLIST *tcrdbmetasearch(RDBQRY **qrys, int num, int type);
// Qry.prototype.metasearch = function( num, type ){};
// TCLIST *tcrdbparasearch(RDBQRY **qrys, int num);
// Qry.prototype.parasearch = function( num ){};

// MARK: RDB
function Hash(){};
package.util.inherits( Hash, TokyoTyrant );
// MARK: RDBTBL
function Table(){};
package.util.inherits( Table, TokyoTyrant );



var command = ['put','putkeep','putcat','putshl','putnr','out','get','mget','vsiz','iterinit','iternext','fwmkeys','addint','adddouble','ext','sync','optimize','vanish','copy','restore','setmst','rnum','size','stat','misc','setindex','genuid'];

function taskCreate( tyrant, cmd, args )
{
	var task = { cmd: cmd };
	
	if( tyrant.constructor === module.exports.Hash ){
		task.protocol = cmd;
		task.args = args;
		task.buf = Protocol[cmd].apply( Protocol, args );
	}
	else if( tyrant.constructor === module.exports.Table )
	{
		switch( cmd )
		{
			case 'put':
			case 'putkeep':
			case 'putcat':
				var pkey = args[0],
					cols = args[1];
					
				if( isString( pkey ) && isObject( cols ) )
				{
					var merge = [pkey];
					
					for( var key in cols ){
						merge.push( key );
						merge.push( cols[key] );
					}
					task.protocol = 'misc';
					task.args = args;
					task.buf = Protocol.misc( cmd, 0, merge );
				}
			break;
			case 'out':
				task.protocol = 'misc';
				task.args = args;
				task.buf = Protocol.misc( cmd, 0, [args[0]] );
			break;
			case 'get':
				task.protocol = 'misc';
				task.args = args;
				task.buf = Protocol.misc( cmd, OPTS.MONOULOG, [args[0]] );
			break;
			case 'setindex':
				task.protocol = 'misc';
				task.args = args;
				task.buf = Protocol.misc( cmd, 0, [args[0],args[1]] );
			break;
			case 'genuid':
				task.protocol = 'misc';
				task.args = args;
				task.buf = Protocol.misc( cmd, 0, [] );
			break;
			
			default:
				task.protocol = cmd;
				task.args = args;
				task.buf = Protocol[cmd].apply( Protocol, args );
		};
	}
	else {
		throw new Error('unknown constructor');
	}
	
	return task;
}

command.forEach( function( cmd )
{
	var method = function()
	{
		var rc = ESUCCESS,
			task = taskCreate( this, cmd, Array.prototype.slice.call( arguments ) );
		
		if( !task.buf ){
			rc = EINVALID;
		}
		else {
			this._task.push( task );
			this.invoke();
		}
		
		return rc;
	};
	
	if( cmd === 'setindex' || cmd === 'genuid' ){
		Table.prototype[cmd] = method;
	}
	else{
		TokyoTyrant.prototype[cmd] = method;
	}
} );

module.exports.Hash = Hash;
module.exports.Table = Table;
module.exports.Qry = Qry;

