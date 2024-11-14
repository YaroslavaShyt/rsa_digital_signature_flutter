import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

class RSAHelper {
  late RSAPublicKey publicKey;
  late RSAPrivateKey privateKey;


  bool verifySignature(Uint8List message, Uint8List signature) {
    final sig = RSASignature(signature);
    final verifier =
        RSASigner(SHA256Digest(), '0609608648016503040201'); 

    verifier.init(false,
        PublicKeyParameter<RSAPublicKey>(publicKey)); 
    try {
      return verifier.verifySignature(message, sig);
    } on ArgumentError {
      return false; 
    }
  }

  Uint8List signMessage(Uint8List message) {
    final signer =
        RSASigner(SHA256Digest(), '0609608648016503040201'); 
    signer.init(true,
        PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(message);
    return signature.bytes;
  }

  Future<void> generateKeyPair(int bitLength) async {
    final secureRandom = SecureRandom('Fortuna')
      ..seed(KeyParameter(Uint8List(32)));

    final keyGen = RSAKeyGenerator();
    keyGen.init(ParametersWithRandom(
      RSAKeyGeneratorParameters(BigInt.parse('65537'), bitLength, 64),
      secureRandom,
    ));

    final pair = keyGen.generateKeyPair();
    publicKey = pair.publicKey as RSAPublicKey;
    privateKey = pair.privateKey as RSAPrivateKey;
  }

  List<int> publicKeyToBytes() {
    final publicKeyInfo = ASN1Sequence()
      ..add(ASN1Integer(publicKey.modulus))
      ..add(ASN1Integer(publicKey.exponent));
    return publicKeyInfo.encode();
  }

  List<int> privateKeyToBytes() {
    final privateKeyInfo = ASN1Sequence()
      ..add(ASN1Integer(privateKey.n))
      ..add(ASN1Integer(privateKey.d))
      ..add(ASN1Integer(privateKey.p))
      ..add(ASN1Integer(privateKey.q));
    return privateKeyInfo.encode();
  }

  String publicKeyToBase64() {
    return base64Encode(publicKeyToBytes());
  }

  String privateKeyToBase64() {
    return base64Encode(privateKeyToBytes());
  }
}

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  final rsaHelper = RSAHelper();
  String publicKeyBase64 = '';
  String privateKeyBase64 = '';
  String message = 'Hello, RSA!';
  String signatureBase64 = '';
  bool isSignatureValid = false;

  @override
  void initState() {
    super.initState();
    generateKeyPair();
  }

  void generateKeyPair() async {
    await rsaHelper.generateKeyPair(2048);
    setState(() {
      publicKeyBase64 = rsaHelper.publicKeyToBase64();
      privateKeyBase64 = rsaHelper.privateKeyToBase64();
    });
  }

  void signMessage() {
    final messageBytes = Uint8List.fromList(utf8.encode(message));
    final signature = rsaHelper.signMessage(messageBytes);
    setState(() {
      signatureBase64 = base64Encode(signature);
    });
  }

  void verifySignature() {
    final messageBytes = Uint8List.fromList(utf8.encode(message));
    final signatureBytes = base64Decode(signatureBase64);
    final isValid = rsaHelper.verifySignature(messageBytes, signatureBytes);
    setState(() {
      isSignatureValid = isValid;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        appBar: AppBar(
          title: const Text('RSA ЕЦП'),
        ),
        body: SingleChildScrollView(
          child: Container(
            margin: const EdgeInsetsDirectional.all(20),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Відкритий ключ (Base64):',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 20,
                  ),
                ),
                SelectableText(publicKeyBase64),
                const SizedBox(height: 16.0),
                const Text(
                  'Закритий ключ (Base64):',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 20,
                  ),
                ),
                SelectableText(privateKeyBase64),
                const SizedBox(height: 16.0),
                TextField(
                  decoration: const InputDecoration(labelText: 'Повідомлення'),
                  controller: TextEditingController(text: message),
                  onChanged: (value) {
                    setState(() {
                      message = value;
                    });
                  },
                ),
                const SizedBox(height: 16.0),
                ElevatedButton(
                  onPressed: signMessage,
                  child: const Text(
                    'Підписати повідомлення',
                  ),
                ),
                const SizedBox(height: 16.0),
                const Text(
                  'Підпис (Base64):',
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 20,
                  ),
                ),
                SelectableText(signatureBase64),
                const SizedBox(height: 16.0),
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    ElevatedButton(
                      onPressed: verifySignature,
                      child: const Text('Перевірити підпис'),
                    ),
                    Text(
                      isSignatureValid
                          ? 'Підпис правильний'
                          : 'Підпис неправильний',
                      style: TextStyle(
                        color: isSignatureValid ? Colors.green : Colors.red,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    Icon(
                      isSignatureValid ? Icons.check : Icons.cancel,
                      color: isSignatureValid ? Colors.green : Colors.red,
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
