module Bip32 = Bip32_ed25519

type vector = {
  secret : Cstruct.t ;
  node : node option ;
  path : int32 list ;
}

and node = {
  kLP : Cstruct.t ;
  kRP : Cstruct.t ;
  cP : Cstruct.t ;
  aP : Cstruct.t ;
}

let cs_encoding =
  let open Json_encoding in
  conv
    (fun cs -> let `Hex hex = Hex.of_cstruct cs in hex)
    (fun hex_str -> Hex.to_cstruct (`Hex hex_str))
    string

let node_encoding =
  let open Json_encoding in
  conv
    (fun { kLP ; kRP ; cP ; aP } -> (kLP, kRP, cP, aP))
    (fun (kLP, kRP, cP, aP) -> { kLP ; kRP ; cP ; aP })
    (obj4
       (req "kLP" cs_encoding)
       (req "kRP" cs_encoding)
       (req "cP" cs_encoding)
       (req "AP" cs_encoding))

let node_or_null_encoding =
  let open Json_encoding in
  union [
    case null (function Some b -> None | None -> Some ()) (fun () -> None) ;
    case node_encoding (function Some b -> Some b | None -> None) (fun n -> Some n)
  ]

let path_encoding =
  let open Json_encoding in
  conv
    Bip32.Human_readable.to_string
    Bip32.Human_readable.of_string_exn
    string

let vector_encoding =
  let open Json_encoding in
  conv
    (fun { secret ; node ; path } -> (secret, node, path))
    (fun (secret, node, path) -> { secret ; node ; path })
    (obj3
       (req "secret" cs_encoding)
       (req "node" node_or_null_encoding)
       (req "path" path_encoding))

module Crypto = struct
  let sha256 = Nocrypto.Hash.SHA256.digest
  let hmac_sha512 = Nocrypto.Hash.SHA512.hmac
end

let with_ic ic ~f =
  try f ic ; close_in ic
  with exn ->
    Format.eprintf "%a@." (Json_encoding.print_error ~print_unknown:(fun ppf _ -> ())) exn ;
    close_in ic ;
    raise exn

let run ic =
  while true do
    let vector = Ezjsonm.from_string (input_line ic) in
    let { secret ; node ; path } =
      Json_encoding.destruct vector_encoding vector in
    match (Bip32.of_seed (module Crypto) secret) with
    | None -> assert (node = None)
    | Some root ->
      match node, (Bip32.derive_path (module Crypto) root path) with
      | Some _, None
      | None, Some _ -> assert false
      | None, None -> ()
      | Some { kLP ; kRP ; cP ; aP }, Some expected_node ->
        let expected_cP = Bip32.chaincode expected_node in
        let expected_ek = Bip32.key expected_node in
        let expected_pk = Tweetnacl.Sign.public expected_ek in
        let expected_aP = Tweetnacl.Sign.to_bytes expected_pk |> Cstruct.of_bigarray in
        let cs = Tweetnacl.Sign.to_bytes expected_ek |> Cstruct.of_bigarray in
        let expected_kLP = Cstruct.sub cs 0 32 in
        let expected_kRP = Cstruct.sub cs 32 32 in

        assert (Cstruct.equal expected_kLP kLP) ;
        assert (Cstruct.equal expected_kRP kRP) ;
        assert (Cstruct.equal expected_aP aP) ;
        assert (Cstruct.equal expected_cP cP) ;
        Printf.eprintf ".%!"
  done

let () =
  let ic = open_in Sys.argv.(1) in
  with_ic ic ~f:begin fun ic ->
    try run ic with End_of_file ->
      Printf.eprintf "\n" ;
      ()
  end
