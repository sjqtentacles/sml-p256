(* demo.sml - generatePublic / ecdh / ecdsaVerify / isOnCurve exercised
   against the published RFC 6979 Appendix A.2.5 (P-256, SHA-256) test
   vectors. All scalars/keys are literal fixed test vectors from the RFC
   (never a real or fabricated private key), so output is deterministic. *)

(* ---- Hex helpers (same shape as test/test.sml) ---- *)
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
        in loop (i + 2, Char.chr (hi * 16 + lo) :: acc) end
  in loop (0, []) end

fun toHex s =
  let
    fun one c =
      let val v = Char.ord c
          val h = v div 16 and l = v mod 16
          fun d n = if n < 10 then Char.chr (Char.ord #"0" + n)
                    else Char.chr (Char.ord #"a" + n - 10)
      in String.implode [d h, d l] end
  in String.concat (List.map one (String.explode s)) end

fun bfromHex h =
  BigInt.fromBytes
    (Word8Vector.fromList (List.map (Word8.fromInt o Char.ord) (String.explode (fromHex h))))

(* ---- RFC 6979 Appendix A.2.5 vectors (P-256, SHA-256, message "sample") ---- *)
val priv   = fromHex "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
val ux     = fromHex "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
val uy     = fromHex "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
val pub    = String.str (Char.chr 0x04) ^ ux ^ uy
val msg    = fromHex "73616D706C65"                          (* ASCII "sample" *)
val r      = bfromHex "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
val s      = bfromHex "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
val sigDer = Asn1.encode (Asn1.Seq [Asn1.Int r, Asn1.Int s])

val gpoint = fromHex
  ("04" ^
   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ^
   "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
val scalarOne = fromHex "0000000000000000000000000000000000000000000000000000000000000001"

val () = print "=== sml-p256 demo (RFC 6979 Appendix A.2.5 vectors) ===\n\n"

val derivedPub = P256.generatePublic priv
val () = print ("generatePublic(priv) matches published pub = "
                ^ Bool.toString (derivedPub = pub) ^ "\n")
val () = print ("public key (hex)      = " ^ toHex derivedPub ^ "\n")

val () = print ("\nisOnCurve(G)           = " ^ Bool.toString (P256.isOnCurve gpoint) ^ "\n")
val () = print ("isOnCurve(pub)         = " ^ Bool.toString (P256.isOnCurve pub) ^ "\n")
val () = print ("isOnCurve(identity)    = " ^ Bool.toString (P256.isOnCurve (fromHex "04")) ^ "\n")

val sh1 = P256.ecdh {privateKey = scalarOne, peerPublic = pub}
val sh2 = P256.ecdh {privateKey = priv, peerPublic = gpoint}
val () = print ("\necdh(1, pub).x  = Ux    = "
                ^ Bool.toString (sh1 = SOME ux) ^ "\n")
val () = print ("ecdh(priv, G).x = Ux    = "
                ^ Bool.toString (sh2 = SOME ux) ^ "\n")

val () = print ("\necdsaVerify(pub, \"sample\", sig)  = "
                ^ Bool.toString (P256.ecdsaVerify {publicKey = pub, message = msg, signatureDer = sigDer})
                ^ "\n")
val () = print ("ecdsaVerify(pub, \"tample\", sig)  = "
                ^ Bool.toString (P256.ecdsaVerify
                    {publicKey = pub, message = fromHex "74616D706C65", signatureDer = sigDer})
                ^ "\n")
