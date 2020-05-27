# HashLib4CSharp
[![License](http://img.shields.io/badge/license-MIT-green.svg)](https://github.com/Xor-el/HashLib4CSharp/blob/master/LICENSE.txt) [![Build Status](https://travis-ci.com/Xor-el/HashLib4CSharp.svg?branch=master)](https://travis-ci.com/Xor-el/HashLib4CSharp) [![Nuget](https://img.shields.io/nuget/v/HashLib4CSharp)](https://www.nuget.org/packages/HashLib4CSharp/) [![Nuget](https://img.shields.io/nuget/dt/HashLib4CSharp)](https://www.nuget.org/packages/HashLib4CSharp/)

HashLib4CSharp is a comprehensive and easy to use hashing library written in C#.
it provides flexible interfaces that makes usage a breeze.
Hashing can be done in single pass or incremental mode.
it also provides methods to clone the internal state of each hash object.

``HashLib4CSharp's`` goal is to be the best option for hashing in C# by offering various hashing primitives via an easy to use API to C# developers.

Development is coordinated on [GitHub](https://github.com/Xor-el/HashLib4CSharp) and contributions are welcome. If you need help, please open an issue [here](https://github.com/Xor-el/HashLib4CSharp/issues).

All functionality of the library is tested using [nunit](https://github.com/nunit/nunit).

### Usage Sample
----------------------------------------


```c#
using System;
using System.Text;
using HashLib4CSharp.Base;

public class Program
{
	public static void Main()
	{
		// single line mode
		var result = HashFactory.Crypto.CreateMD5().ComputeString("Hello C#", Encoding.UTF8).ToString();
		Console.WriteLine(result);
		// split mode
		var hash = HashFactory.Crypto.CreateMD5();
		hash.Initialize();
		hash.TransformString("Hello", Encoding.UTF8);
		hash.TransformString(" C#", Encoding.UTF8);
		result = hash.TransformFinal().ToString();
		Console.WriteLine(result);
	}
}
```

More usage samples can be found in ``HashLib4CSharp.Tests`` folder.

### Tip Jar
----------------------------------------

* :dollar: **Bitcoin**: `1MhFfW7tDuEHQSgie65uJcAfJgCNchGeKf`
* :euro: **Ethereum**: `0x6c1DC21aeC49A822A4f1E3bf07c623C2C1978a98`
* :pound: **Pascalcoin**: `345367-40`
