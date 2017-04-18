'use strict';

const lo = require('lodash');
const randomstring = require('randomstring');
const isStream = require('is-stream');
const yn = require('yn');
const Promise = require('bluebird');
const jwt = require('jsonwebtoken');

const util = exports = module.exports = {};

// UUID

util.uuid = require('uuid/v4');

// Promise

util.Promise = Promise;

// JWT

util.jwt = Object.freeze({
  encode(payload, secret) {
    return jwt.sign(payload, secret);
  },
  decode(token, secret) {
    return jwt.verify(token, secret);
  },
});

// Yes/No
util.yn = yn;
util.y = (v) => yn(v) === true;
util.n = (v) => yn(v) === false;

// Function Combiners

util.not = lo.negate;
util.and = (...funcs) => (value) => lo.every(funcs, (func) => func(value));
util.or = (...funcs) => (value) => lo.some(funcs, (func) => func(value));

// Utility Methods from Lodash

util.noop = lo.noop;
util.attempt = lo.attempt;
util.range = lo.range;
util.fallback = (...args) => lo.find(args, (v) => v !== '' || v != null);

// Collection Methods from Lodash

util.all = lo.every;
util.any = lo.some;
util.forEach = lo.forEach;
util.find = lo.find;
util.includes = lo.includes;
util.reduce = lo.reduce;
util.filter = lo.filter;
util.reject = lo.reject;
util.size = lo.size;

// Object Methods from Lodash

util.get = lo.get;
util.set = lo.set;
util.has = lo.has;
util.update = lo.update;
util.unset = lo.unset;
util.keys = lo.keys;
util.values = lo.values;
util.mapKeys = lo.mapKeys;
util.mapValues = lo.mapValues;
util.defaults = lo.defaults;
util.pick = lo.pick;
util.pickBy = lo.pickBy;
util.only = (object, selector) => (
  lo.isFunction(selector)
    ? lo.pickBy(object, selector)
    : lo.pick(object, selector)
);
util.entries = lo.entries;
util.transform = lo.transform;

// String Methods from Lodash

util.toCamelCase = lo.camelCase;
util.toSnakeCase = lo.snakeCase;
util.toKebabCase = lo.kebabCase;
util.toPascalCase = (s) => lo.upperFirst(lo.camelCase(s));
util.trim = lo.trim;
util.words = lo.words;

// Function Methods from Lodash

util.curry = lo.curry;
util.curryRight = lo.curryRight;
util.debounce = lo.debounce;
util.delay = lo.delay;
util.memoize = lo.memoize;
util.negate = lo.negate;
util.once = lo.once;
util.throttle = lo.throttle;
util.unary = lo.unary;

// Type Checks

util.isArray = lo.isArray;
util.isBoolean = util.isBool = lo.isBoolean;
util.isBuffer = lo.isBuffer;
util.isDate = lo.isDate;
util.isEmpty = lo.isEmpty;
util.isNonEmptyString = util.and(lo.isString, util.not(lo.isEmpty));
util.isError = lo.isError;
util.isFunction = util.isFunc = lo.isFunction;
util.isInteger = lo.isInteger;
util.isMap = lo.isMap;
util.isNaN = util.isNan = lo.isNaN;
util.isNil = lo.isNil;
util.isNull = lo.isNull;
util.isNumber = lo.isNumber;
util.isObject = lo.isObject;
util.isPlainObject = lo.isPlainObject;
util.isPromise = (v) => (v && lo.isFunction(v.then));
util.isRegExp = util.isRegex = lo.isRegExp;
util.isSet = lo.isSet;
util.isStream = isStream;
util.isReadStream = isStream.readable;
util.isWriteStream = isStream.writeable;
util.isString = lo.isString;
util.isSymbol = lo.isSymbol;
util.isTypedArray = lo.isTypedArray;
util.isUndefined = lo.isUndefined;
util.isWeakMap = lo.isWeakMap;
util.isWeakSet = lo.isWeakSet;

// Type Casting

util.toArray = lo.toArray;
util.toInteger = lo.toInteger;
util.toNumber = lo.toNumber;
util.toPlainObject = lo.toPlainObject;
util.toString = lo.toString;
util.toPairs = lo.toPairs;
util.fromPairs = lo.fromPairs;

// Date

util.now = () => new Date();
util.iso = () => (new Date()).toISOString();
util.timestamp = () => (new Date()).valueOf(); // in milliseconds

// Presence

util.isExisty = (v) => v != null;
util.isFalsey = (v) => !v;
util.isTruthy = (v) => !!v;

// String Format Checks via Regex

const REGEX = Object.freeze({
  AFFIRMATIVE: /^(?:1|t(?:rue)?|y(?:es)?|ok(?:ay)?)$/,
  ALPHA_NUMERIC: /^[A-Za-z0-9]+$/,
  CREDIT_CARD: /^(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))$/,
  EMAIL: /^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|\.|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$/i,
  HEXADECIMAL: /^(?:0x)?[0-9a-fA-F]+$/,
  ISO: /^([\+-]?\d{4}(?!\d{2}\b))((-?)((0[1-9]|1[0-2])(\3([12]\d|0[1-9]|3[01]))?|W([0-4]\d|5[0-2])(-?[1-7])?|(00[1-9]|0[1-9]\d|[12]\d{2}|3([0-5]\d|6[1-6])))([T\s]((([01]\d|2[0-3])((:?)[0-5]\d)?|24\:?00)([\.,]\d+(?!:))?)?(\17[0-5]\d([\.,]\d+)?)?([zZ]|([\+-])([01]\d|2[0-3]):?([0-5]\d)?)?)?)?$/,
  IPV4: /^(?:(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:\d|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])$/,
  IPV6: /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i,
  JWT: /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/i,
  PHONE: /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/,
  SOCIAL_SECURITY_NUMBER: /^(?!000|666)[0-8][0-9]{2}-?(?!00)[0-9]{2}-?(?!0000)[0-9]{4}$/,
  URL: /^(?:(?:https?|ftp):\/\/)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)(?:\.(?:[a-z\u00a1-\uffff0-9]-*)*[a-z\u00a1-\uffff0-9]+)*(?:\.(?:[a-z\u00a1-\uffff]{2,})))(?::\d{2,5})?(?:\/\S*)?$/i,
  UUID_STRICT: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  ZIPCODE: /^[0-9]{5}(?:-[0-9]{4})?$/,
});

const regexTester = (regex) => {
  return (v) => v != null && regex.test(v);
};

util.isAffirmative = regexTester(REGEX.AFFIRMATIVE);
util.isAlphaNumeric = regexTester(REGEX.ALPHA_NUMERIC);
util.isCreditCard = regexTester(REGEX.CREDIT_CARD);
util.isEmail = regexTester(REGEX.EMAIL);
util.isHexadecimal = util.isHexaDecimal = regexTester(REGEX.HEXADECIMAL);
util.isIso = util.isISO = regexTester(REGEX.ISO);
util.isIpv4 = util.isIPv4 = util.isIPV4 = regexTester(REGEX.IPV4);
util.isIpv6 = util.IPv6 = util.isIPV6 = regexTester(REGEX.IPV6);
util.isIp = util.isIP = util.isIpAddress = util.or(util.isIpv4, util.isIpv6);
util.isJwt = util.isJWT = regexTester(REGEX.JWT);
util.isPhone = util.isPhoneNumber = regexTester(REGEX.PHONE);
util.isSSN = util.isSocialSecurityNumber = regexTester(REGEX.SOCIAL_SECURITY_NUMBER);
util.isUrl = util.isURL = regexTester(REGEX.URL);
util.isUuidStrict = regexTester(REGEX.UUID_STRICT);
util.isUuid = util.isUUID = regexTester(REGEX.UUID);
util.isZipcode = util.isZipCode = regexTester(REGEX.ZIPCODE);

// Randomization

const DEFAULT_STRING_LENGTH = 32;
const randstr = (config = {}) => {
  return (length) => {
    let options = lo.assign({}, config);
    options.length = lo.isInteger(length) ? length : DEFAULT_STRING_LENGTH;
    options.readable = lo.isBoolean(config.readable) ? config.readable : true;
    return randomstring.generate(options);
  };
};

const random = util.random = {};
random.number = lo.random;
random.integer = lo.partialRight(lo.random, false);
random.float = lo.partialRight(lo.random, true);
random.string = randstr();
random.alpha = randstr({ charset: 'alphabetic' });
random.alphanumeric = randstr({ charset: 'alphanumeric' });
random.hex = randstr({ charset: 'hex' });
random.numeric = randstr({ charset: 'numeric' });
random.lowercase = randstr({ charset: 'alphabetic', capitalization: 'lowercase' });
random.uppercase = randstr({ charset: 'alphabetic', capitalization: 'uppercase' });
util.randomstring = randomstring.generate;

// Type Checkers

const is = util.is = {};

// Formats
is.affirmation = util.isAffirmative;
is.alphanumeric = util.isAlphaNumeric;
is.creditcard = util.isCreditCard;
is.email = util.isEmail;
is.hexadecimal = util.isHexadecimal;
is.iso = util.isIso; // ISO 8601
is.ipv4 = util.isIpv4;
is.ipv6 = util.isIpv6;
is.ip = util.isIp;
is.jwt = util.isJwt;
is.phone = util.isPhone;
is.ssn = util.isSocialSecurityNumber;
is.url = util.isUrl;
is.uuid = util.isUuid;
is.zipcode = util.isZipcode;

// Types
is.array = util.isArray;
is.bool = is.boolean = util.isBoolean;
is.buffer = util.isBuffer; // Buffer.isBuffer
is.date = util.isDate;
is.empty = util.isEmpty;
is.nonEmptyString = util.isNonEmptyString;
is.error = util.isError;
is.fn = is.func = is.function = util.isFunction;
is.int = is.integer = util.isInteger;
is.nan = util.isNaN;
is.nil = util.isNil;
is.null = util.isNull;
is.number = util.isNumber;
is.object = util.isObject;
is.pojo = is.plainObject = util.isPlainObject;
is.regex = is.regexp = util.isRegExp;
is.stream = util.isStream;
is.readstream = util.isReadStream;
is.writestream = util.isWriteStream;
// @NOTE: https://github.com/sindresorhus/is-stream
// is.stream.readable
// is.stream.writable
// is.stream.duplex
// is.stream.transform
is.string = util.isString;
is.symbol = util.isSymbol;
is.undefined = util.isUndefined;

// Presence
is.existy = util.isExisty;
is.falsey = util.isFalsey;
is.truthy = util.isTruthy;

// Numbers
is.positive = (n) => is.number(n) && n > 0;
is.negative = (n) => is.number(n) && n < 0;
is.even = (n) => is.number(n) && n % 2 === 0;
is.odd = (n) => is.number(n) && n % 2 === 1;
is.decimal = (n) => is.number(n) && n % 1 !== 0;
is.infinite = (n) => n === Infinity || n === -Infinity;
is.finite = (n) => is.number(n) && !is.nan(n) && !is.infinite(n);

// Promises

is.promise = util.isPromise;
is.bluebird = (v) => is.promise(v) && util.all([v.isFulFilled, v.isRejected, v.isPending, v.value, v.tap], util.isFunction);
is.resolved = (v) => is.promise(v) && Promise.resolve(v).isFulFilled();
is.rejected = (v) => is.promise(v) && Promise.resolve(v).isRejected();
is.pending = (v) => is.promise(v) && Promise.resolve(v).isPending();
