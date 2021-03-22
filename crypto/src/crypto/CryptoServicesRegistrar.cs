using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Org.BouncyCastle.Crypto
{
	/**
     * Basic registrar class for providing defaults for cryptography services in this module.
     */

	public static class CryptoServicesRegistrar
	{
		private static bool CanSetDefaultProperty = true; // WTF JAVA? If this is needed in C# add to config file. 
		private static bool CanSetThreadProperty = true;
		private static bool CanSetDefaultRandom = true;

		private static ThreadLocal<Dictionary<string, dynamic>> ThreadProperties = new ThreadLocal<Dictionary<string, dynamic>>();
		private static Dictionary<string, dynamic> GlobalProperties = new Dictionary<string, dynamic>();

		private static object cacheLock = new object();
		private static SecureRandom defaultSecureRandom;

		// default domain parameters for DSA and Diffie-Hellman
		public static void Init()
		{
			DSAParameters def512Params = new DSAParameters
			{
				P = (new BigInteger("fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17", 16)).ToByteArrayUnsigned(),
				Q = (new BigInteger("962eddcc369cba8ebb260ee6b6a126d9346e38c5", 16)).ToByteArrayUnsigned(),
				G = (new BigInteger("678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca4", 16)).ToByteArrayUnsigned(),
				Seed = Hex.DecodeStrict("b869c82b35d70e1b1ff91b28e37a62ecdc34409b"),
				Counter = 123
			};

			DSAParameters def768Params = new DSAParameters()
			{
				P = new BigInteger("e9e642599d355f37c97ffd3567120b8e25c9cd43e927b3a9670fbec5" +
							   "d890141922d2c3b3ad2480093799869d1e846aab49fab0ad26d2ce6a" +
							   "22219d470bce7d777d4a21fbe9c270b57f607002f3cef8393694cf45" +
							   "ee3688c11a8c56ab127a3daf", 16).ToByteArrayUnsigned(),
				Q = new BigInteger("9cdbd84c9f1ac2f38d0f80f42ab952e7338bf511", 16).ToByteArrayUnsigned(),
				G = new BigInteger("30470ad5a005fb14ce2d9dcd87e38bc7d1b1c5facbaecbe95f190aa7" +
							   "a31d23c4dbbcbe06174544401a5b2c020965d8c2bd2171d366844577" +
							   "1f74ba084d2029d83c1c158547f3a9f1a2715be23d51ae4d3e5a1f6a" +
							   "7064f316933a346d3f529252", 16).ToByteArrayUnsigned(),
				Seed = Hex.DecodeStrict("77d0f8c4dad15eb8c4f2f8d6726cefd96d5bb399"),
				Counter = 263
			};

			DSAParameters def1024Params = new DSAParameters()
			{
				P = new BigInteger("fd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80" +
								"b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b" +
								"801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c6" +
								"1bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675" +
								"f3ae2b61d72aeff22203199dd14801c7", 16).ToByteArrayUnsigned(),
				Q = new BigInteger("9760508f15230bccb292b982a2eb840bf0581cf5", 16).ToByteArrayUnsigned(),
				G = new BigInteger("f7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b" +
								"3d0782675159578ebad4594fe67107108180b449167123e84c281613" +
								"b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f" +
								"0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06" +
								"928b665e807b552564014c3bfecf492a", 16).ToByteArrayUnsigned(),
				Seed = Hex.DecodeStrict("8d5155894229d5e689ee01e6018a237e2cae64cd"),
				Counter = 92
			};

			DSAParameters def2048Params = new DSAParameters()
			{
				P = new BigInteger("95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5b" +
								"b2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f4" +
								"8076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2" +
								"c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa" +
								"65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73b" +
								"e3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79" +
								"506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6" +
								"147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa906" +
								"50d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2" +
								"a406cb0b", 16).ToByteArrayUnsigned(),
				Q = new BigInteger("f8183668ba5fc5bb06b5981e6d8b795d30b8978d43ca0ec572e37e09939a9773", 16).ToByteArrayUnsigned(),
				G = new BigInteger("42debb9da5b3d88cc956e08787ec3f3a09bba5f48b889a74aaf53174" +
								"aa0fbe7e3c5b8fcd7a53bef563b0e98560328960a9517f4014d3325f" +
								"c7962bf1e049370d76d1314a76137e792f3f0db859d095e4a5b93202" +
								"4f079ecf2ef09c797452b0770e1350782ed57ddf794979dcef23cb96" +
								"f183061965c4ebc93c9c71c56b925955a75f94cccf1449ac43d586d0" +
								"beee43251b0b2287349d68de0d144403f13e802f4146d882e057af19" +
								"b6f6275c6676c8fa0e3ca2713a3257fd1b27d0639f695e347d8d1cf9" +
								"ac819a26ca9b04cb0eb9b7b035988d15bbac65212a55239cfc7e58fa" +
								"e38d7250ab9991ffbc97134025fe8ce04c4399ad96569be91a546f49" +
								"78693c7a", 16).ToByteArrayUnsigned(),
				Seed = Hex.DecodeStrict("b0b4417601b59cbc9d8ac8f935cadaec4f5fbb2f23785609ae466748d9b5a536"),
				Counter = 497
			};
			//localSetGlobalProperty(Property.DSA_DEFAULT_PARAMS, def512Params, def768Params, def1024Params, def2048Params);
			//localSetGlobalProperty(Property.DH_DEFAULT_PARAMS, toDH(def512Params), toDH(def768Params), toDH(def1024Params), toDH(def2048Params));
		}

		/**
		 * Return the default source of randomness.
		 *
		 * @return the default SecureRandom
		 */
		public static SecureRandom GetSecureRandom()
		{
			lock (cacheLock)
			{
				if (null != defaultSecureRandom)
				{
					return defaultSecureRandom;
				}
			}

			SecureRandom tmp = new SecureRandom();

			lock (cacheLock)
			{
				if (null == defaultSecureRandom)
				{
					defaultSecureRandom = tmp;
				}

				return defaultSecureRandom;
			}
		}

		/**
		 * Return either the passed-in SecureRandom, or if it is null, then the default source of randomness.
		 *
		 * @param secureRandom the SecureRandom to use if it is not null.
		 * @return the SecureRandom parameter if it is not null, or else the default SecureRandom
		 */
		public static SecureRandom GetSecureRandom(SecureRandom secureRandom)
		{
			return null == secureRandom ? GetSecureRandom() : secureRandom;
		}

		/**
		 * Set a default secure random to be used where none is otherwise provided.
		 *
		 * @param secureRandom the SecureRandom to use as the default.
		 */
		public static void SetSecureRandom(SecureRandom secureRandom)
		{
			//checkPermission(CanSetDefaultRandom);

			lock (cacheLock)
			{
				defaultSecureRandom = secureRandom;
			}
		}

		/**
		 * Return the default value for a particular property if one exists. The look up is done on the thread's local
		 * configuration first and then on the global configuration in no local configuration exists.
		 *
		 * @param property the property to look up.
		 * @param <T> the type to be returned
		 * @return null if the property is not set, the default value otherwise,
		 */
		public static object GetProperty<T>(Property property)
		{
			T[] values = lookupProperty<T>(property);

			if (values != null)
			{
				return values[0];
			}

			return null;
		}

		private static T[] lookupProperty<T>(Property property)
		{
			Dictionary<string, dynamic> properties = ThreadProperties.Value;
			T[] values;

			if (properties == null || !properties.ContainsKey(property.Name))
			{
				values = GlobalProperties[property.Name] as T[];
			}
			else
			{
				values = properties[property.Name].ToArray<T>();
			}
			return values;
		}

		/**
		 * Return an array representing the current values for a sized property such as DH_DEFAULT_PARAMS or
		 * DSA_DEFAULT_PARAMS.
		 *
		 * @param property the name of the property to look up.
		 * @param <T> the base type of the array to be returned.
		 * @return null if the property is not set, an array of the current values otherwise.
		 */
		public static T[] GetSizedProperty<T>(Property property)
		{
			T[] values = lookupProperty<T>(property);

			if (values == null)
			{
				return null;
			}

			return values.ToArray();
		}

		/**
		 * Return the value for a specific size for a sized property such as DH_DEFAULT_PARAMS or
		 * DSA_DEFAULT_PARAMS.
		 *
		 * @param property the name of the property to look up.
		 * @param size the size (in bits) of the defining value in the property type.
		 * @param <T> the type of the value to be returned.
		 * @return the current value for the size, null if there is no value set,
		 */
		public static T GetSizedProperty<T>(Property property, int size) where T : class
		{
			T[] values = lookupProperty<T>(property);

			if (values == null)
			{
				return null;
			}

			if (property.Type.IsAssignableFrom(typeof(DHParameters)))

			{
				for (int i = 0; i != values.Length; i++)
				{
					DHParameters dHParameters = values[i] as DHParameters;

					if (dHParameters.P.BitLength == size)
					{
						return dHParameters as T;
					}
				}
			}

			else if (property.Type.IsAssignableFrom(typeof(DSAParameters)))
			{
				for (int i = 0; i != values.Length; i++)
				{
					List<DSAParameters> dSAParameters = values[i] as List<DSAParameters>;

					if (dSAParameters.Count() == size)
					{
						return dSAParameters as T;
					}
				}
			}

			return null;
		}

		/**
		 * Set the value of the the passed in property on the current thread only. More than
		 * one value can be passed in for a sized property. If more than one value is provided the
		 * first value in the argument list becomes the default value.
		 *
		 * @param property the name of the property to set.
		 * @param propertyValue the values to assign to the property.
		 * @param <T> the base type of the property value.
		 */
		public static void SetThreadProperty<T>(Property property, List<T> propertyValue) where T : class
		{
			// checkPermission(CanSetThreadProperty); // Nah, I'm good. 

			if (!property.Type.IsAssignableFrom(typeof(T)))
			{
				throw new InvalidParameterException("Bad propertyValue passed");
			}

			localSetThread(property, propertyValue.ToList<T>());
		}

		/**
		 * Set the value of the the passed in property globally in the JVM. More than
		 * one value can be passed in for a sized property. If more than one value is provided the
		 * first value in the argument list becomes the default value.
		 *
		 * @param property the name of the property to set.
		 * @param propertyValue the values to assign to the property.
		 * @param <T> the base type of the property value.
		 */
		public static void SetGlobalProperty<T>(Property property, List<T> propertyValue)

		{
			// checkPermission(CanSetDefaultProperty); // Must suck programming Java

			LocalSetGlobalProperty<T>(property, propertyValue.ToList<T>());
		}

		private static void localSetThread<T>(Property property, List<T> propertyValue)

		{
			Dictionary<string, List<T>> properties = ThreadProperties.Value.ContainsKey(property.Name) ? ThreadProperties.Value[property.Name] : null;

			if (properties == null)
			{
				properties = new Dictionary<string, List<T>>();
				ThreadProperties.Value.Add(property.Name, properties);
			}

			properties.Add(property.Name, propertyValue);
		}

		private static void LocalSetGlobalProperty<T>(Property property, List<T> propertyValue)

		{
			if (!property.Type.IsAssignableFrom(typeof(T)))
			{
				throw new InvalidParameterException("Bad property value passed");
			}

			// set the property for the current thread as well to avoid mass confusion
			localSetThread(property, propertyValue);

			GlobalProperties.Add(property.Name, propertyValue);
		}

		/**
		 * Clear the global value for the passed in property.
		 *
		 * @param property the property to be cleared.
		 * @param <T> the base type of the property value
		 * @return an array of T if a value was previously set, null otherwise.
		 */
		public static bool ClearGlobalProperty<T>(Property property)
		{
			// checkPermission(CanSetDefaultProperty); // I can do what I want

			// clear the property for the current thread as well to avoid confusion
			LocalClearThreadProperty<T>(property);

			return GlobalProperties.Remove(property.Name);
		}

		/**
		 * Clear the thread local value for the passed in property.
		 *
		 * @param property the property to be cleared.
		 * @param <T> the base type of the property value
		 * @return an array of T if a value was previously set, null otherwise.
		 */
		public static bool ClearThreadProperty<T>(Property property)

		{
			// checkPermission(CanSetThreadProperty); // Respect My Authority

			return LocalClearThreadProperty<T>(property);
		}

		private static bool LocalClearThreadProperty<T>(Property property)
		{
			Dictionary<string, List<T>> properties = !ThreadProperties.Value.ContainsKey(property.Name) ? null : ThreadProperties.Value[property.Name];

			if (properties == null)
			{
				properties = new Dictionary<string, List<T>>();
				ThreadProperties.Value[property.Name].Add(properties);
			}

			return properties.Remove(property.Name);
		}

		//private static void checkPermission(Permission permission)
		//{
		//	//final SecurityManager securityManager = System.getSecurityManager();

		//	//if (securityManager != null)
		//	//{
		//	//	AccessController.doPrivileged(new PrivilegedAction<Object>()
		//	//	{

		//	//	public Object run()
		//	//	{
		//	//		securityManager.checkPermission(permission);

		//	//		return null;
		//	//	}
		//	//});
		//}
	}

	internal static class CryptoServiceRegistrarHelpers
	{
		internal static DHParameters ToDH(DSAParameters dsaParams)
		{
			int pSize = dsaParams.P.Length;
			int m = ChooseLowerBound(pSize);
			return new DHParameters(new BigInteger(dsaParams.P), new BigInteger(dsaParams.G), new BigInteger(dsaParams.Q), m, 0, null, new DHValidationParameters(dsaParams.Seed, dsaParams.Counter));
		}

		// based on lower limit of at least 2^{2 * bits_of_security}
		internal static int ChooseLowerBound(int pSize)
		{
			int m = 160;
			if (pSize > 1024)
			{
				if (pSize <= 2048)
				{
					m = 224;
				}
				else if (pSize <= 3072)
				{
					m = 256;
				}
				else if (pSize <= 7680)
				{
					m = 384;
				}
				else
				{
					m = 512;
				}
			}
			return m;
		}
	}

	/**
	 * Available properties that can be set.
	 */
	public class Property
	{
		/**
		 * The parameters to be used for processing implicitlyCA X9.62 parameters
		 */
		public static Property EC_IMPLICITLY_CA = new Property("ecImplicitlyCA", typeof(X9ECParameters));
		/**
		 * The default parameters for a particular size of Diffie-Hellman key.This is a sized property.
		 */
		public static Property DH_DEFAULT_PARAMS = new Property("dhDefaultParams", typeof(DHParameters));
		/**
		 * The default parameters for a particular size of DSA key. This is a sized property.
		 */
		public static Property DSA_DEFAULT_PARAMS = new Property("dsaDefaultParams", typeof(DSAParameters));

		public string Name
		{
			get; set;
		}
		public Type Type { get; set; }

		private Property(string name, Type type)
		{
			Name = name;
			Type = type;
		}
	}
}