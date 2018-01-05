open Tweetnacl
open Bip32_ed25519

module Crypto = struct
  let sha256 = Nocrypto.Hash.SHA256.digest
  let hmac_sha512 = Nocrypto.Hash.SHA512.hmac
end

let c = (module Crypto : CRYPTO)

let gen_key () =
  let rec inner i =
    try i, of_seed c (Rand.gen 32) with _ -> inner (succ i)
  in inner 0

let basic () =
  let i, sk = gen_key () in
  let pk = neuterize sk in
  let sk' = derive c sk 0l in
  let pk' = derive c pk 0l in
  let pk'' = neuterize sk' in
  Format.printf "\n%a\n%a\n" pp pk' pp pk'';
  assert (equal pk' pk'')

module HR = struct
  open Human_readable
  let of_string () =
    match of_string "44'/1'/0'/0/0" with
    | None -> assert false
    | Some [a; b; c; 0l; 0l] when
        a = to_hardened 44l &&
        b = to_hardened 1l &&
        c = to_hardened 0l -> ()
    | _ -> assert false

  let to_string () =
    let res =
      to_string [to_hardened 44l; to_hardened 1l; to_hardened 0l; 0l; 0l] in
    Printf.printf "%s\n%!" res ;
    assert (res = "44'/1'/0'/0/0") ;
    let res = to_string [] in
    assert (res = "") ;
    let res = to_string [to_hardened 2l; 123l] in
    assert (res = "2'/123")

  let of_string_exn_fail () =
    match of_string_exn "//" with
    | exception _ -> ()
    | _ -> assert false

  let of_string_exn_success () =
    ignore (of_string_exn "") ;
    ignore (of_string_exn "1/2") ;
    ignore (of_string_exn "1/2'/3'/0") ;
    ()
end

let basic = [
  "basic", `Quick, basic ;
]

let human_readable = HR.[
    "of_string", `Quick, of_string ;
    "of_string_exn_fail", `Quick, of_string_exn_fail ;
    "of_string_exn_success", `Quick, of_string_exn_success ;
    "to_string", `Quick, to_string ;
  ]

let () =
  Alcotest.run "Bip32_ed25519" [
    "basic", basic ;
    "human_readable", human_readable ;
  ]
