open Sodium
open Bip32_ed25519
module SM = Scalar_mult.Ed25519

let () = Random.stir ()

let point_of_group_elt ge =
  ge |> SM.Bigbytes.of_group_elt |> ECArith.Bigbytes.to_point

let group_elt_of_point p =
  p |> ECArith.Bigbytes.of_point |> SM.Bigbytes.to_group_elt

let pk_of_group_elt ge =
  ge |> SM.Bigbytes.of_group_elt |> Sign.Bigbytes.to_public_key

let group_elt_of_pk pk =
  pk |> Sign.Bigbytes.of_public_key |> SM.Bigbytes.to_group_elt

let point_of_pk pk =
  pk |> Sign.Bigbytes.of_public_key |> ECArith.Bigbytes.to_point

let pk_of_point point =
  point |> ECArith.Bigbytes.of_point |> Sign.Bigbytes.to_public_key

let integer_of_sk sk =
  sk |> Sign.Bigbytes.of_secret_key |> fun ba ->
  Bigarray.Array1.sub ba 0 32 |>
  SM.Bigbytes.to_integer

let gen_key () =
  let rec inner i =
    try
      let seed =
        Random.Bigbytes.generate 32 |> Sign.Bigbytes.to_seed in
      i, of_seed seed
    with _ -> inner (succ i)
  in inner 0

let library () =
  let i, sk = gen_key () in
  let sk = key sk in
  let pk = Sign.secret_key_to_public_key sk in
  let pk' = SM.base (integer_of_sk sk) |> pk_of_group_elt in
  Format.printf "\n%a\n%a\n"
    Hex.pp (Sign.Bigbytes.of_public_key pk |> Cstruct.of_bigarray |> Hex.of_cstruct)
    Hex.pp (Sign.Bigbytes.of_public_key pk' |> Cstruct.of_bigarray |> Hex.of_cstruct) ;
  assert (Sign.equal_public_keys pk pk')

let basic () =
  let i, sk = gen_key () in
  let pk = neuterize sk in
  let sk' = derive sk 0l in
  let pk' = derive pk 0l in
  let pk'' = neuterize sk' in
  Format.printf "\n%a\n%a\n" pp pk' pp pk'';
  assert (pk' = pk'')

let basic = [
  "library", `Quick, library ;
  (* "basic", `Quick, basic ; *)
]

let () =
  Alcotest.run "Bip32_ed25519" [
    "basic", basic ;
  ]
