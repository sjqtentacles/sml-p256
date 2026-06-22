(* Tests for sml-p256 (Track A4, Phase 3b).

   Vectors:
     - RFC 6979 Appendix A.2.5 (P-256, SHA-256) gives a published
       (privateKey, publicKey, message, r, s) tuple with a valid
       deterministic ECDSA signature.  This is an *external* oracle:
       generatePublic(priv) must equal the published public key, and
       ecdsaVerify(pub, msg, DER(r,s)) must be true.  It also yields an
       ECDH known-answer: since d*G = pub, ecdh(d, G).x = pub.x, and
       since 1*Q = Q, ecdh(1, pub).x = pub.x — both expected values
       come from the RFC, not from this implementation.
     - Point-validation rejection of off-curve / identity / malformed
       inputs.
     - Malformed-input handling: bad DER / bad public key yield
       `false` / `NONE` rather than exceptions. *)

structure P256Tests =
struct
  open Harness

  (* ---- Hex helpers ----
     Published vectors are hex; we decode to raw bytes since the library
     works in raw byte strings. *)
  fun nib c =
    if c >= #"0" andalso c <= #"9" then Char.ord c - Char.ord #"0"
    else if c >= #"a" andalso c <= #"f" then Char.ord c - Char.ord #"a" + 10
    else if c >= #"A" andalso c <= #"F" then Char.ord c - Char.ord #"A" + 10
    else ~1

  fun fromHex s =
    let
      fun isSpace c = c = #" " orelse c = #"\n" orelse c = #"\t" orelse c = #"\r"
      val cleaned = String.implode (List.filter (not o isSpace) (String.explode s))
      val n = String.size cleaned
      fun loop (i, acc) =
        if i >= n then String.implode (List.rev acc)
        else
          let
            val hi = nib (String.sub (cleaned, i))
            val lo = if i + 1 < n then nib (String.sub (cleaned, i + 1)) else 0
          in
            if hi < 0 orelse lo < 0 then raise Fail "bad hex"
            else loop (i + 2, Char.chr (hi * 16 + lo) :: acc)
          end
    in
      loop (0, [])
    end

  fun toHex s =
    let
      fun one c =
        let val v = Char.ord c
            val h = v div 16 and l = v mod 16
            fun d n = if n < 10 then Char.chr (Char.ord #"0" + n)
                      else Char.chr (Char.ord #"a" + n - 10)
        in String.implode [d h, d l] end
    in String.concat (List.map one (String.explode s)) end

  fun bytesEq (a, b) = String.size a = String.size b andalso a = b

  fun bytes [] = ""
    | bytes (n :: ns) = String.str (Char.chr n) ^ bytes ns

  fun str2 a b = bytes [a, b]

  fun checkBytes (name, expected, actual) =
    if bytesEq (expected, actual) then check name true
    else
      let val () = print ("  FAIL - " ^ name ^ ": " ^ toHex expected ^ " <> " ^ toHex actual ^ "\n")
      in check name false end

  (* Big-endian unsigned bytes -> BigInt (for building DER signatures). *)
  fun bfromHex h =
    BigInt.fromBytes
      (Word8Vector.fromList
         (List.map (Word8.fromInt o Char.ord) (String.explode (fromHex h))))

  (* =====================================================================
     P-256 domain parameters (SEC2 / FIPS 186-4).
     ===================================================================== *)
  val p  = bfromHex "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
  val Gx = bfromHex "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
  val Gy = bfromHex "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"

  val g_point = fromHex
    ("04" ^
     "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ^
     "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")

  (* =====================================================================
     RFC 6979 Appendix A.2.5 — P-256, SHA-256, message "sample".
     These are the published deterministic-ECDSA vectors and act as the
     external oracle for both generatePublic and ecdsaVerify.
     ===================================================================== *)
  val rfc_priv = fromHex "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
  val rfc_Ux   = fromHex "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
  val rfc_Uy   = fromHex "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
  val rfc_pub  = String.str (Char.chr 0x04) ^ rfc_Ux ^ rfc_Uy

  (* ASCII "sample" — the message in RFC 6975 A.2.5. *)
  val rfc_msg  = fromHex "73616D706C65"

  (* Valid deterministic signature (r, s) over SHA-256("sample"). *)
  val rfc_r = bfromHex "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
  val rfc_s = bfromHex "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
  val rfc_sigDer = Asn1.encode (Asn1.Seq [Asn1.Int rfc_r, Asn1.Int rfc_s])

  (* A second RFC 6979 vector: message "test" with the SAME key.  Its
     signature is valid over "test" but NOT over "sample", so it serves
     as a false-case against the "sample" message. *)
  val rfc_r_test = bfromHex "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"
  val rfc_s_test = bfromHex "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"
  val rfc_sigDer_test = Asn1.encode (Asn1.Seq [Asn1.Int rfc_r_test, Asn1.Int rfc_s_test])

  (* The scalar 1, as a 32-byte big-endian key. *)
  val scalar_one = fromHex "0000000000000000000000000000000000000000000000000000000000000001"

  (* =====================================================================
     Point-validation vectors.
     ===================================================================== *)

  (* Off-curve: X = Gx, Y = 2 (not a square root of x^3-3x+b mod p). *)
  val off_curve = fromHex
    ("04" ^
     "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ^
     "0000000000000000000000000000000000000000000000000000000000000002")

  (* Identity / point-at-infinity encoded as bare 0x04 (malformed). *)
  val identity = fromHex "04"

  val too_short = fromHex "0401"
  val too_long  = fromHex ("04" ^ String.concat (List.tabulate (66, fn _ => "00")))
  val bad_prefix = fromHex ("05" ^ String.concat (List.tabulate (64, fn _ => "00")))

  (* =====================================================================
     The suite.
     ===================================================================== *)

  fun run () =
    let
      val () = section "P-256 (A4)"

      (* ---- generatePublic: RFC 6979 KAT ----
         priv = C9AF...F6721  ==>  pub = 04 || Ux || Uy  (published). *)
      val pub1 = P256.generatePublic rfc_priv
      val () = checkBytes ("generatePublic: RFC 6979 public key", rfc_pub, pub1)
      val () = check "generatePublic: result is on curve" (P256.isOnCurve pub1)

      (* ---- isOnCurve ---- *)
      val () = check "isOnCurve: base point G" (P256.isOnCurve g_point)
      val () = check "isOnCurve: RFC 6979 public key" (P256.isOnCurve rfc_pub)
      val () = check "isOnCurve: off-curve point -> false" (not (P256.isOnCurve off_curve))
      val () = check "isOnCurve: identity (0x04) -> false" (not (P256.isOnCurve identity))
      val () = check "isOnCurve: too short -> false" (not (P256.isOnCurve too_short))
      val () = check "isOnCurve: too long -> false" (not (P256.isOnCurve too_long))
      val () = check "isOnCurve: bad prefix -> false" (not (P256.isOnCurve bad_prefix))

      (* ---- ECDH known-answer (two independent vectors) ----
         KAT 1: ecdh(1, Q) = 1*Q = Q  ==>  shared.x = Q.x = Ux.
         KAT 2: ecdh(d, G) = d*G = Q  ==>  shared.x = Q.x = Ux.
         Both expected values are the published Ux. *)
      val sh1 = P256.ecdh {privateKey = scalar_one, peerPublic = rfc_pub}
      val () = case sh1 of
                 SOME s => checkBytes ("ECDH KAT 1 (1*Q): shared X = Ux", rfc_Ux, s)
               | NONE   => check "ECDH KAT 1 (1*Q): shared X = Ux" false

      val sh2 = P256.ecdh {privateKey = rfc_priv, peerPublic = g_point}
      val () = case sh2 of
                 SOME s => checkBytes ("ECDH KAT 2 (d*G): shared X = Ux", rfc_Ux, s)
               | NONE   => check "ECDH KAT 2 (d*G): shared X = Ux" false

      (* ECDH with a bad peer public key returns NONE, not an exception. *)
      val () = case P256.ecdh {privateKey = rfc_priv, peerPublic = off_curve} of
                 NONE => check "ECDH: off-curve peer -> NONE" true
               | _    => check "ECDH: off-curve peer -> NONE" false
      val () = case P256.ecdh {privateKey = rfc_priv, peerPublic = identity} of
                 NONE => check "ECDH: identity peer -> NONE" true
               | _    => check "ECDH: identity peer -> NONE" false
      val () = case P256.ecdh {privateKey = rfc_priv, peerPublic = too_short} of
                 NONE => check "ECDH: malformed peer -> NONE" true
               | _    => check "ECDH: malformed peer -> NONE" false

      (* ---- ECDSA verify ---- *)
      (* True case: the RFC 6979 signature over "sample" verifies. *)
      val () = check "ecdsaVerify: RFC 6979 valid signature -> true"
                     (P256.ecdsaVerify {publicKey = rfc_pub,
                                        message = rfc_msg,
                                        signatureDer = rfc_sigDer})

      (* False case: the "test" signature does NOT verify over "sample". *)
      val () = check "ecdsaVerify: signature for wrong message -> false"
                     (not (P256.ecdsaVerify {publicKey = rfc_pub,
                                             message = rfc_msg,
                                             signatureDer = rfc_sigDer_test}))

      (* False case: tampered message. *)
      val () = check "ecdsaVerify: tampered message -> false"
                     (not (P256.ecdsaVerify {publicKey = rfc_pub,
                                             message = fromHex "74616D706C65", (* "tample" *)
                                             signatureDer = rfc_sigDer}))

      (* False case: bad public key -> false. *)
      val () = check "ecdsaVerify: off-curve public key -> false"
                     (not (P256.ecdsaVerify {publicKey = off_curve,
                                             message = rfc_msg,
                                             signatureDer = rfc_sigDer}))
      val () = check "ecdsaVerify: identity public key -> false"
                     (not (P256.ecdsaVerify {publicKey = identity,
                                             message = rfc_msg,
                                             signatureDer = rfc_sigDer}))

      (* Malformed DER -> false (NOT an exception). *)
      val () = check "ecdsaVerify: malformed DER (garbage) -> false"
                     (not (P256.ecdsaVerify {publicKey = rfc_pub,
                                             message = rfc_msg,
                                             signatureDer = fromHex "00"}))
      val () = check "ecdsaVerify: empty DER -> false"
                     (not (P256.ecdsaVerify {publicKey = rfc_pub,
                                             message = rfc_msg,
                                             signatureDer = ""}))
      val () = check "ecdsaVerify: truncated DER -> false"
                     (not (P256.ecdsaVerify {publicKey = rfc_pub,
                                             message = rfc_msg,
                                             signatureDer = fromHex "30"}))
    in
      ()
    end
end
