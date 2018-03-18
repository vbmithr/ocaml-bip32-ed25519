module Bip32 = Bip32_ed25519

let member_str m j =
  Yojson.Basic.Util.(member m j |> to_string)

let member = Yojson.Basic.Util.member

module Crypto = struct
  let sha256 = Nocrypto.Hash.SHA256.digest
  let hmac_sha512 = Nocrypto.Hash.SHA512.hmac
end


let () =
  let line = ref 0 in
  try
    while true do
      let vector = Yojson.Basic.from_string (input_line stdin) in
      let secret = Hex.to_cstruct (`Hex (member_str "secret" vector))
      and path   = member_str "path" vector in
      let chain  = match (Bip32.Human_readable.of_string path) with
        | Some path -> path
        | None -> failwith "invalid derivation path" in

      let vector_node = member "node" vector in

      begin
        match (Bip32.of_seed (module Crypto) secret) with
        | None -> assert (vector_node = `Null)
        | Some root -> match (Bip32.derive_path (module Crypto) root chain) with
          | None -> assert (vector_node = `Null)
          | Some node ->
            let `Hex cP = Hex.of_cstruct (Bip32.chaincode node)
            and ekey = Bip32.key node in
            let pkey = Tweetnacl.Sign.public ekey in
            let `Hex aP = Tweetnacl.Sign.to_cstruct pkey |> Hex.of_cstruct
            and cs = Tweetnacl.Sign.to_cstruct ekey in
            let `Hex kLP = Cstruct.sub cs 0 32  |> Hex.of_cstruct
            and `Hex kRP = Cstruct.sub cs 32 32 |> Hex.of_cstruct in

            assert ((member "kLP" vector_node) = `String kLP);
            assert ((member "kRP" vector_node) = `String kRP);
            assert ((member "AP" vector_node)  = `String  aP);
            assert ((member "cP" vector_node)  = `String cP)
      end;
      Printf.printf "passed vector %d\n" !line;
      line := !line + 1;
    done
  with End_of_file ->
    ()
