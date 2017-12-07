// crypto:加密模块， querystring:查询字符串。
var crypto = require('crypto')
  , qs = require('querystring')
  ;
//  sha1(key,body)函数：运用crypto.createHmac(algorithm, key[, options]):创建并返回一个对象，以一个密钥和一个消息为输入，
//   生成一个加密串作为输出。（key:密钥，body:未被加密的数据） 
function sha1 (key, body) {
  return crypto.createHmac('sha1', key).update(body).digest('base64')
}

// rsa(key,body)函数：运用crypto.createSign(algorithm[, options]):创建并返回使用给定算法的符号对象。

function rsa (key, body) {
  return crypto.createSign("RSA-SHA1").update(body).sign(key, 'base64');
}
// rfc3986(str)函数：RFC是Request for Comments首字母的缩写，它是IETF（互联网工程任务推进组织）的一个无限制分发文档。
// RFC被编号并且用编号来标识。
// encodeURIComponent()函数：可将字符串作为URI组件进行编码，其返回值URIstring的副本，
//  其中某些字符串将被十六进制的转义序列进行替换。
function rfc3986 (str) {
  return encodeURIComponent(str)
  //使用正则表达式进行一系列的替换。
    .replace(/!/g,'%21')
    .replace(/\*/g,'%2A')
    .replace(/\(/g,'%28')
    .replace(/\)/g,'%29')
    .replace(/'/g,'%27')
    ;
}

// Maps object to bi-dimensional array
// Converts { foo: 'A', bar: [ 'b', 'B' ]} to
// [ ['foo', 'A'], ['bar', 'b'], ['bar', 'B'] ]
//将对象映射到二维数组
function map (obj) {
  var key, val, arr = []
  for (key in obj) {
    val = obj[key]
    if (Array.isArray(val))
      for (var i = 0; i < val.length; i++)
        arr.push([key, val[i]])
    else if (typeof val === "object")
      for (var prop in val)
        arr.push([key + '[' + prop + ']', val[prop]]);
    else
      arr.push([key, val])
  }
  return arr
}

// 比较排序函数
function compare (a, b) {
  return a > b ? 1 : a < b ? -1 : 0
}

function generateBase (httpMethod, base_uri, params) {
  // 改编自 https://dev.twitter.com/docs/auth/oauth and 
  // https://dev.twitter.com/docs/auth/creating-signature

  // 参数归一化
  // http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
  var normalized = map(params)
  //  1. 首先，对每个参数的名称和值进行编码。
  .map(function (p) {
    return [ rfc3986(p[0]), rfc3986(p[1] || '') ]
  })
  //  2.  这些参数按照名称排序，使用升序字节值。
  //  如果两个或者多个参数共享相同的名称，则按照它们的值排序。
  
  .sort(function (a, b) {
    return compare(a[0], b[0]) || compare(a[1], b[1])
  })
  //  3.每个参数的名称被连接到相应的值，使用“=”字符（ASCII代码61）作为分隔符，即使值是空的。  
  .map(function (p) { return p.join('=') })
   // 4. 将排序的名称/值连在一起，使用“&”字符（ASCII代码38）作为分离器。

  .join('&')

  //调用rfc3986()函数，将字符串进行编码。
  var base = [
    rfc3986(httpMethod ? httpMethod.toUpperCase() : 'GET'),
    rfc3986(base_uri),
    rfc3986(normalized)
  ].join('&')

  return base
}
// 调用generateBase() map() sha1()函数，最后实现用HAMC-SHAI算法得到一个加密串。
function hmacsign (httpMethod, base_uri, params, consumer_secret, token_secret) {
  var base = generateBase(httpMethod, base_uri, params)
  var key = [
    consumer_secret || '',
    token_secret || ''
  ].map(rfc3986).join('&')

  return sha1(key, base)
}
// 调用generateBase() rsa()函数，最后实现使用RSA-SHAI算法得到一个符号对象。
function rsasign (httpMethod, base_uri, params, private_key, token_secret) {
  var base = generateBase(httpMethod, base_uri, params)
  var key = private_key || ''

  return rsa(key, base)
}
// 调用 map()函数，最后实现使用PLAINTEXT算法得到密钥。
function plaintext (consumer_secret, token_secret) {
  var key = [
    consumer_secret || '',
    token_secret || ''
  ].map(rfc3986).join('&')

  return key
}
//  不同的方法匹配相应的函数
function sign (signMethod, httpMethod, base_uri, params, consumer_secret, token_secret) {
  var method
  var skipArgs = 1

  switch (signMethod) {
    case 'RSA-SHA1':
      method = rsasign
      break
    case 'HMAC-SHA1':
      method = hmacsign
      break
    case 'PLAINTEXT':
      method = plaintext
      skipArgs = 4
      break
    default:
     throw new Error("Signature method not supported: " + signMethod)
  }

  return method.apply(null, [].slice.call(arguments, skipArgs))
}

// 使用exports方法后，下面的这些函数都变成了公开的。
exports.hmacsign = hmacsign
exports.rsasign = rsasign
exports.plaintext = plaintext
exports.sign = sign
exports.rfc3986 = rfc3986
exports.generateBase = generateBase
