project "mbedtls"
	kind "StaticLib"
	language "C++"

	targetdir ("bin/" .. outputdir .. "/%{prj.name}")
	objdir ("bin-int/" .. outputdir .. "/%{prj.name}")

	files
	{
	    "library/aes.c",
        "library/aesni.c",
        "library/aesce.c",
        "library/aria.c",
        "library/asn1parse.c",
        "library/asn1write.c",
        "library/base64.c",
        "library/bignum.c",
        "library/bignum_core.c",
        "library/bignum_mod.c",
        "library/bignum_mod_raw.c",
        "library/camellia.c",
        "library/ccm.c",
        "library/chacha20.c",
        "library/chachapoly.c",
        "library/cipher.c",
        "library/cipher_wrap.c",
        "library/constant_time.c",
        "library/cmac.c",
        "library/ctr_drbg.c",
        "library/des.c",
        "library/dhm.c",
        "library/ecdh.c",
        "library/ecdsa.c",
        "library/ecjpake.c",
        "library/ecp.c",
        "library/ecp_curves.c",
        "library/entropy.c",
        "library/entropy_poll.c",
        "library/gcm.c",
        "library/hash_info.c",
        "library/hkdf.c",
        "library/hmac_drbg.c",
        "library/lmots.c",
        "library/lms.c",
        "library/md.c",
        "library/md5.c",
        "library/memory_buffer_alloc.c",
        "library/nist_kw.c",
        "library/oid.c",
        "library/padlock.c",
        "library/pem.c",
        "library/pk.c",
        "library/pk_wrap.c",
        "library/pkcs12.c",
        "library/pkcs5.c",
        "library/pkparse.c",
        "library/pkwrite.c",
        "library/platform.c",
        "library/platform_util.c",
        "library/poly1305.c",
        "library/psa_crypto.c",
        "library/psa_crypto_aead.c",
        "library/psa_crypto_cipher.c",
        "library/psa_crypto_client.c",
        "library/psa_crypto_ecp.c",
        "library/psa_crypto_hash.c",
        "library/psa_crypto_mac.c",
        "library/psa_crypto_pake.c",
        "library/psa_crypto_rsa.c",
        "library/psa_crypto_se.c",
        "library/psa_crypto_slot_management.c",
        "library/psa_crypto_storage.c",
        "library/psa_its_file.c",
        "library/psa_util.c",
        "library/ripemd160.c",
        "library/rsa.c",
        "library/rsa_alt_helpers.c",
        "library/sha1.c",
        "library/sha256.c",
        "library/sha512.c",
        "library/threading.c",
        "library/timing.c",
        "library/version.c",
        "include/mbedtls/**.h"
	}

	includedirs
	{
		"include"
	}

	filter "system:windows"
		systemversion "latest"
		cppdialect "C++17"
		staticruntime "off"

	filter "system:linux"
		pic "On"
		systemversion "latest"
		cppdialect "C++17"
		staticruntime "off"

	filter "configurations:Debug"
		runtime "Debug"
		symbols "on"

	filter "configurations:Release"
		runtime "Release"
		optimize "on"

