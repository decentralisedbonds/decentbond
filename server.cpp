/*********************************************************************
 *  rsa2048_server.cpp –  cpp‑httplib + OpenSSL (HTTPS only)
 *
 *  * Added per‑key “analysis bonds” support.
 *  * /setAnalysisBonds – authenticated, clears previous bonds first.
 *  * /getAnalysisBonds – public read, no authentication.
 *  * All persistent stores now load from disk on start and write back
 *    immediately after any mutation.  Each store uses its own JSON file.
 *  * Added GDPR endpoints and per‑client authentication.
 *
 *  * **HTTPS only** – key file is ssl.key (PEM containing cert + key).
 *
 *********************************************************************/

#include <iostream>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <mutex>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <optional>
#include <fstream>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>          // <-- added for HTTPS

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"                 // single‑header HTTP/HTTPS server
#include "nlohmann/json.hpp"          // nlohmann/json (single header)

using json = nlohmann::json;

/* --------------------------------------------------------------------- */
/*  Debug helper – can be turned off by defining NDEBUG or changing the
 *  macro.  The macro prints the file/line where it was invoked, which
 *  helps pinpoint where a message came from.                                 */
/* --------------------------------------------------------------------- */
#ifndef NDEBUG
#define DBG(msg) \
std::cerr << "[DEBUG] (" << __FILE__ << ":" << __LINE__ << ") " << msg << std::endl << std::endl
#else
#define DBG(msg) /* no‑op */
#endif

/* --------------------------------------------------------------------- */
/*  Helpers – base64 (URL‑SAFE, no padding) – we use OpenSSL           */
/* --------------------------------------------------------------------- */
static std::string base64_urlsafe_no_pad(const unsigned char* in, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    std::string out(out_len, '\0');
    int encoded = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), in, len);

    out.resize(encoded);                     // remove padding
    std::replace(out.begin(), out.end(), '+', '-');
    std::replace(out.begin(), out.end(), '/', '_');
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

static bool base64_urlsafe_no_pad_decode(const std::string& in,
                                         std::vector<unsigned char>& out) {
    std::string tmp = in;
    std::replace(tmp.begin(), tmp.end(), '-', '+');
    std::replace(tmp.begin(), tmp.end(), '_', '/');

    while (tmp.size() % 4) tmp.push_back('=');

    size_t out_len = 3 * tmp.size() / 4;
    out.resize(out_len);
    int decoded = EVP_DecodeBlock(out.data(),
                                  reinterpret_cast<const unsigned char*>(tmp.data()),
                                  tmp.size());
    if (decoded < 0) return false;
    out.resize(decoded);
    return true;
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  RSA key handling                                                    */
                                         /* --------------------------------------------------------------------- */
                                         class RSAKeyPair
                                         {
                                         public:
                                             RSAKeyPair() : rsa_(nullptr) {}
                                             ~RSAKeyPair() { if (rsa_) RSA_free(rsa_); }

                                             bool loadPEM(const std::string& path)
                                             {
                                                 FILE* fp = fopen(path.c_str(), "rb");
                                                 if (!fp) { perror("fopen"); return false; }
                                                 RSA* r = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
                                                 fclose(fp);
                                                 if (!r) { printErr("PEM_read_RSAPrivateKey"); return false; }
                                                 rsa_ = r;
                                                 //DBG("Loaded RSA private key from " << path);
                                                 return true;
                                             }

                                             bool writePEM(const std::string& path) const
                                             {
                                                 FILE* fp = fopen(path.c_str(), "wb");
                                                 if (!fp) { perror("fopen"); return false; }
                                                 int ok = PEM_write_RSAPrivateKey(fp, rsa_, nullptr, nullptr, 0, nullptr, nullptr);
                                                 fclose(fp);
                                                 if (!ok) { printErr("PEM_write_RSAPrivateKey"); return false; }
                                                 //DBG("Saved RSA private key to " << path);
                                                 return true;
                                             }

                                             bool generate(int bits = 2048)
                                             {
                                                 rsa_ = RSA_new();
                                                 BIGNUM* e = BN_new();
                                                 BN_set_word(e, RSA_F4);
                                                 if (RSA_generate_key_ex(rsa_, bits, e, nullptr) != 1) {
                                                     printErr("RSA_generate_key_ex");
                                                     BN_free(e);
                                                     return false;
                                                 }
                                                 BN_free(e);
                                                 //DBG("Generated new RSA key pair (" << bits << " bits)");
                                                 return true;
                                             }

                                             std::string publicKeyB64() const
                                             {
                                                 if (!rsa_) return "";
                                                 int len = i2d_RSA_PUBKEY(rsa_, nullptr);
                                                 std::vector<unsigned char> buf(len);
                                                 unsigned char* p = buf.data();
                                                 i2d_RSA_PUBKEY(rsa_, &p);
                                                 return base64_urlsafe_no_pad(buf.data(), buf.size());
                                             }

                                             std::vector<unsigned char> sign(const std::vector<unsigned char>& data) const
                                             {
                                                 std::vector<unsigned char> sig(RSA_size(rsa_));
                                                 unsigned int siglen;
                                                 if (RSA_sign(NID_sha256, data.data(),
                                                     static_cast<int>(data.size()),
                                                              sig.data(), &siglen, rsa_) != 1) {
                                                     printErr("RSA_sign");
                                                 return {};
                                                              }
                                                              sig.resize(siglen);
                                                              //DBG("Signed data of length " << data.size() << " with RSA key");
                                                              return sig;
                                             }

                                         private:
                                             void printErr(const char* msg) const
                                             {
                                                 unsigned long err = ERR_get_error();
                                                 char buf[256];
                                                 ERR_error_string_n(err, buf, sizeof(buf));
                                                 std::cerr << msg << ": " << buf << std::endl;
                                             }

                                             RSA* rsa_;
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Persistent store base class                                          */
                                         /* --------------------------------------------------------------------- */
                                         class FileBackedStore
                                         {
                                         public:
                                             FileBackedStore(const std::string& file_path) : file_path_(file_path) { load(); }
                                             virtual ~FileBackedStore() = default;

                                         protected:
                                             std::string file_path_;
                                             std::mutex mtx_;

                                             bool load()
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 std::ifstream ifs(file_path_);
                                                 if (!ifs.is_open()) {
                                                     //DBG("No existing file for " << file_path_ << " – starting with empty store");
                                                     return true;   // nothing to load
                                                 }
                                                 try {
                                                     json j;
                                                     ifs >> j;
                                                     if (!loadFromJson(j)) {
                                                         //DBG("Failed to load JSON from " << file_path_);
                                                         return false;
                                                     }
                                                     //DBG("Loaded store from " << file_path_);
                                                     return true;
                                                 } catch (const std::exception& e) {
                                                     //DBG("Exception while loading " << file_path_ << ": " << e.what());
                                                     return false;
                                                 }
                                             }

                                             bool save() const
                                             {
                                                 //std::lock_guard<std::mutex> lock(mtx_);
                                                 json j = toJson();
                                                 std::ofstream ofs(file_path_);
                                                 if (!ofs.is_open()) {
                                                     //DBG("Failed to open file for writing: " << file_path_);
                                                     return false;
                                                 }
                                                 ofs << std::setw(4) << j << '\n';
                                                 //DBG("Saved store to " << file_path_);
                                                 return true;
                                             }

                                             virtual bool loadFromJson(const json&) { return true; }
                                             virtual json toJson() const { return json::object(); }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  In‑memory key ↔ IP store + username & info, persisted to file      */
                                         /* --------------------------------------------------------------------- */
                                         class KVStore : public FileBackedStore
                                         {
                                         public:
                                             explicit KVStore(const std::string& file_path) : FileBackedStore(file_path) {load();}

                                             using Meta = struct { std::string username; std::string info; };



                                             bool addOrUpdate(const std::string& pk,
                                                              const std::string& username = "",
                                                              const std::string& info = "")
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 store_[pk] = {username, info};
                                                 //DBG("KVStore: added/updated key " << pk);
                                                 return save();
                                             }

                                             std::optional<Meta> lookup(const std::string& pk) const
                                             {
                                                 auto it = store_.find(pk);
                                                 if (it == store_.end()) return std::nullopt;
                                                 return it->second;
                                             }

                                             void erase(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 store_.erase(pk);
                                                 //DBG("KVStore: erased key " << pk);
                                                 save();
                                             }

                                         private:
                                             std::unordered_map<std::string, Meta> store_;

                                             bool loadFromJson(const json& j) override
                                             {
                                                 for (auto& [key, val] : j.items()) {
                                                     Meta m;
                                                     m.username  = val.value("username", "");
                                                     m.info      = val.value("info", "");
                                                     store_[key] = m;
                                                 }
                                                 return true;
                                             }

                                             json toJson() const override
                                             {
                                                 json j;
                                                 for (const auto& [key, meta] : store_) {
                                                     j[key] = {
                                                         {"username", meta.username},
                                                         {"info", meta.info}
                                                     };
                                                 }
                                                 return j;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Agreements store – public key → {name, datetime, contact, revoked}   */
                                         /* --------------------------------------------------------------------- */
                                         class AgreementsStore : public FileBackedStore
                                         {
                                         public:
                                             explicit AgreementsStore(const std::string& file_path) : FileBackedStore(file_path) {load();}


                                             using Meta = struct {
                                                 std::string name;
                                                 std::string datetime;
                                                 std::string contact;
                                                 bool revoked = false;          // NEW: revocation flag
                                             };


                                             bool addOrUpdate(const std::string& pk,
                                                              const std::string& name,
                                                              const std::string& datetime,
                                                              const std::string& contact)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 store_[pk] = {name, datetime, contact, false};
                                                 //DBG("AgreementsStore: added/updated key " << pk);
                                                 return save();
                                             }

                                             std::optional<Meta> lookup(const std::string& pk) const
                                             {
                                                 auto it = store_.find(pk);
                                                 if (it == store_.end()) return std::nullopt;
                                                 return it->second;
                                             }

                                             bool contains(const std::string& pk) const
                                             {
                                                 return store_.find(pk) != store_.end();
                                             }

                                             /* NEW: set revocation flag */
                                             void setRevoked(const std::string& pk, bool revoked)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 auto it = store_.find(pk);
                                                 if (it != store_.end()) {
                                                     it->second.revoked = revoked;
                                                     //DBG("AgreementsStore: key " << pk << " revoked=" << revoked);
                                                     save();
                                                 }
                                             }

                                             /* NEW: query revocation status */
                                             bool isRevoked(const std::string& pk) const
                                             {
                                                 auto it = store_.find(pk);
                                                 if (it == store_.end()) return false;
                                                 return it->second.revoked;
                                             }

                                             void erase(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 store_.erase(pk);
                                                 //DBG("AgreementsStore: erased key " << pk);
                                                 save();
                                             }

                                         private:
                                             std::unordered_map<std::string, Meta> store_;

                                             bool loadFromJson(const json& j) override
                                             {
                                                 for (auto& [key, val] : j.items()) {
                                                     Meta m;
                                                     m.name      = val.value("name", "");
                                                     m.datetime  = val.value("datetime", "");
                                                     m.contact   = val.value("contact", "");
                                                     m.revoked   = val.value("revoked", false);   // NEW
                                                     store_[key] = m;
                                                 }
                                                 return true;
                                             }

                                             json toJson() const override
                                             {
                                                 json j;
                                                 for (const auto& [key, meta] : store_) {
                                                     j[key] = {
                                                         {"name", meta.name},
                                                         {"datetime", meta.datetime},
                                                         {"contact", meta.contact},
                                                         {"revoked", meta.revoked}
                                                     };
                                                 }
                                                 return j;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Bonds buffer – one per public key, persisted to file                 */
                                         /* --------------------------------------------------------------------- */
                                         class BondsStore : public FileBackedStore
                                         {
                                         public:
                                             explicit BondsStore(const std::string& file_path) : FileBackedStore(file_path) {load();}

                                             bool add(const std::string& pk, const std::string& bond_json)
                                             {
                                                 buffer_[pk].push_back(bond_json);
                                                 //DBG("BondsStore: added bond for " << pk);
                                                 return save();
                                             }

                                             std::vector<std::string> consume(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 auto it = buffer_.find(pk);
                                                 if (it == buffer_.end()) return {};
                                                 auto vec = std::move(it->second);
                                                 buffer_.erase(it);
                                                 //DBG("BondsStore: consumed bonds for " << pk);
                                                 save();
                                                 return vec;
                                             }

                                             void clear(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 buffer_.erase(pk);
                                                 //DBG("BondsStore: cleared bonds for " << pk);
                                                 save();
                                             }

                                             void erase(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 buffer_.erase(pk);
                                                 //DBG("BondsStore: erased bonds for " << pk);
                                                 save();
                                             }

                                         private:
                                             std::unordered_map<std::string, std::vector<std::string>> buffer_;

                                             bool loadFromJson(const json& j) override
                                             {
                                                 for (auto& [key, val] : j.items()) {
                                                     if (val.is_array()) {
                                                         std::vector<std::string> vec;
                                                         for (auto& el : val) vec.push_back(el.get<std::string>());
                                                         buffer_[key] = std::move(vec);
                                                     }
                                                 }
                                                 return true;
                                             }

                                             json toJson() const override
                                             {
                                                 json j;
                                                 for (const auto& [key, vec] : buffer_) {
                                                     j[key] = vec;
                                                 }
                                                 return j;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  AnalysisBonds buffer – one per public key, persisted to file          */
                                         /* --------------------------------------------------------------------- */
                                         class AnalysisBondsStore : public FileBackedStore
                                         {
                                         public:
                                             explicit AnalysisBondsStore(const std::string& file_path) : FileBackedStore(file_path) {load();}

                                             bool set(const std::string& pk, const std::vector<std::string>& bonds)
                                             {
                                                 buffer_[pk] = bonds;
                                                 //DBG("AnalysisBondsStore: set bonds for " << pk);
                                                 return save();
                                             }

                                             std::vector<std::string> get(const std::string& pk) const
                                             {
                                                 auto it = buffer_.find(pk);
                                                 if (it == buffer_.end()) return {};
                                                 return it->second;
                                             }

                                             void erase(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 buffer_.erase(pk);
                                                 //DBG("AnalysisBondsStore: erased bonds for " << pk);
                                                 save();
                                             }

                                         private:
                                             std::unordered_map<std::string, std::vector<std::string>> buffer_;

                                             bool loadFromJson(const json& j) override
                                             {
                                                 for (auto& [key, val] : j.items()) {
                                                     if (val.is_array()) {
                                                         std::vector<std::string> vec;
                                                         for (auto& el : val) vec.push_back(el.get<std::string>());
                                                         buffer_[key] = std::move(vec);
                                                     }
                                                 }
                                                 return true;
                                             }

                                             json toJson() const override
                                             {
                                                 json j;
                                                 for (const auto& [key, vec] : buffer_) {
                                                     j[key] = vec;
                                                 }
                                                 return j;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Nonce store – one per public key, persisted to file                  */
                                         /* --------------------------------------------------------------------- */
                                         class NonceStore : public FileBackedStore
                                         {
                                         public:
                                             explicit NonceStore(const std::string& file_path) : FileBackedStore(file_path) {load();}

                                             bool set(const std::string& pk, const std::vector<unsigned char>& nonce)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 nonce_[pk] = nonce;
                                                 //DBG("NonceStore: set nonce for " << pk);
                                                 return save();
                                             }

                                             std::vector<unsigned char> get(const std::string& pk) const
                                             {
                                                 auto it = nonce_.find(pk);
                                                 if (it == nonce_.end()) return {};
                                                 return it->second;
                                             }

                                             void erase(const std::string& pk)
                                             {
                                                 std::lock_guard<std::mutex> lock(mtx_);
                                                 nonce_.erase(pk);
                                                 //DBG("NonceStore: erased nonce for " << pk);
                                                 save();
                                             }

                                         private:
                                             std::unordered_map<std::string, std::vector<unsigned char>> nonce_;

                                             bool loadFromJson(const json& j) override
                                             {
                                                 for (auto& [key, val] : j.items()) {
                                                     if (val.is_string()) {
                                                         std::vector<unsigned char> vec;
                                                         base64_urlsafe_no_pad_decode(val.get<std::string>(), vec);
                                                         nonce_[key] = std::move(vec);
                                                     }
                                                 }
                                                 return true;
                                             }

                                             json toJson() const override
                                             {
                                                 json j;
                                                 for (const auto& [key, vec] : nonce_) {
                                                     j[key] = base64_urlsafe_no_pad(vec.data(), vec.size());
                                                 }
                                                 return j;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  RSA verification helper                                             */
                                         /* --------------------------------------------------------------------- */
                                         static bool verify_signature(const std::string& pk_b64,
                                                                      const std::vector<unsigned char>& msg,
                                                                      const std::vector<unsigned char>& sig)
                                         {
                                             std::vector<unsigned char> pk_der;
                                             if (!base64_urlsafe_no_pad_decode(pk_b64, pk_der)) return false;

                                             const unsigned char* p = pk_der.data();
                                             RSA* rsa = d2i_RSA_PUBKEY(nullptr, &p, pk_der.size());
                                             if (!rsa) return false;

                                             EVP_PKEY* evp_pub = EVP_PKEY_new();
                                             EVP_PKEY_assign_RSA(evp_pub, rsa);    // rsa is now owned by evp_pub

                                             EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                                             if (!ctx) { EVP_PKEY_free(evp_pub); return false; }

                                             bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, evp_pub) == 1 &&
                                             EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) == 1 &&
                                             EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1;

                                             EVP_MD_CTX_free(ctx);
                                             EVP_PKEY_free(evp_pub);

                                             //DBG("Signature verification " << (ok ? "succeeded" : "failed") << " for key " << pk_b64);
                                             return ok;
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  Verify nonce and consume it (used for authenticated endpoints)      */
                                         /* --------------------------------------------------------------------- */
                                         static bool verify_and_consume_nonce(const std::string& pk_b64,
                                                                              const std::vector<unsigned char>& sig,
                                                                              NonceStore& ns)
                                         {
                                             auto nonce = ns.get(pk_b64);
                                             if (nonce.empty()) {
                                                 //DBG("Nonce not found for key " << pk_b64);
                                                 return false;
                                             }
                                             if (!verify_signature(pk_b64, nonce, sig)) {
                                                 //DBG("Nonce signature verification failed for key " << pk_b64);
                                                 return false;
                                             }
                                             ns.erase(pk_b64);
                                             //DBG("Nonce consumed for key " << pk_b64);
                                             return true;
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  Client authorization – now also checks revocation                   */
                                         /* --------------------------------------------------------------------- */
                                         static bool client_authorized(const std::string& client_pk,
                                                                       const AgreementsStore& agreements)
                                         {
                                             bool auth = agreements.contains(client_pk) && !agreements.isRevoked(client_pk);
                                             //DBG("Client authorization for key " << client_pk << ": " << (auth ? "ok" : "denied"));
                                             return auth;
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  Main entry point                                                     */
                                         /* --------------------------------------------------------------------- */
                                         int main(int argc, char* argv[])
                                         {
                                             /* ------------------------------------------------------------------ */
                                             /*  OpenSSL initialization                                          */
                                             /* ------------------------------------------------------------------ */
                                             OpenSSL_add_all_algorithms();
                                             ERR_load_BIO_strings();
                                             ERR_load_crypto_strings();
                                             SSL_library_init();          // required for SSLServer
                                             SSL_load_error_strings();
                                             //DBG("OpenSSL initialized");

                                             /* ------------------------------------------------------------------ */
                                             /*  Command‑line parsing                                            */
                                             /* ------------------------------------------------------------------ */
                                             std::string host = "0.0.0.0";
                                             int port = 643;

                                             auto usage = [&](const std::string& msg = "") {
                                                 if (!msg.empty()) std::cerr << msg << '\n';
                                                 std::cerr << "Usage: server [-h host] [-p port]\n";
                                                 return 1;
                                             };

                                             for (int i = 1; i < argc; ++i) {
                                                 std::string arg = argv[i];
                                                 if ((arg == "-h" || arg == "--host") && i + 1 < argc) {
                                                     host = argv[++i];
                                                 } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
                                                     try { port = std::stoi(argv[++i]); }
                                                     catch (...) { return usage("Invalid port number"); }
                                                 } else if (arg == "-?" || arg == "--help") {
                                                     return usage();
                                                 } else {
                                                     return usage("Unknown option: " + arg);
                                                 }
                                             }

                                             //std::cout << "Starting HTTPS server on " << host << ":" << port << '\n';
                                             //DBG("Server will listen on " << host << ":" << port);

                                             /* ------------------------------------------------------------------ */
                                             /*  Persistent stores                                               */
                                             /* ------------------------------------------------------------------ */
                                             KVStore kv("kvstore.json");
                                             BondsStore bonds("bonds.json");
                                             AnalysisBondsStore analysisBonds("analysis.json");
                                             NonceStore nonces("nonces.json");
                                             AgreementsStore agreements("agreements.json");

                                             constexpr size_t NONCE_LEN = 32;

                                             /* ------------------------------------------------------------------ */
                                             /*  HTTPS server (httplib::SSLServer)                                */
                                             /* ------------------------------------------------------------------ */
                                             httplib::SSLServer svr([](ssl_ctx_st &ctx) -> bool {
                                                 // Load the server certificate
                                                 if (SSL_CTX_use_certificate_chain_file(&ctx, "fullchain.pem") != 1) {
                                                     std::cerr << "Failed to load certificate\n";
                                                 return false;   // abort construction
                                                     }

                                                     // Load the private key that matches the certificate
                                                     if (SSL_CTX_use_PrivateKey_file(&ctx, "privkey.pem",
                                                         SSL_FILETYPE_PEM) != 1) {
                                                         std::cerr << "Failed to load private key\n";
                                                     return false;
                                                         }

                                                         // Optional: make sure the private key matches the cert
                                                         if (SSL_CTX_check_private_key(&ctx) != 1) {
                                                             std::cerr << "Private key does not match the certificate\n";
                                                             return false;
                                                         }

                                                         // Optional: enable TLSv1.2+ only
                                                         SSL_CTX_set_options(&ctx, SSL_OP_ALL);

                                                         //DBG("SSL context successfully initialized");
                                                         return true;   // success
                                             });

                                             // Make sure the server was initialised correctly
                                             if (!svr.is_valid()) {
                                                 std::cerr << "Could not initialise SSL server\n";
                                                 return 1;
                                             }

                                             /* ------------------------------------------------------------------ */
                                             /*  /challenge – GET – requires public_key param                     */
                                             /* ------------------------------------------------------------------ */
                                             svr.Get("/challenge", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /challenge request");
                                                 std::string pk_b64 = req.get_param_value("public_key");
                                                 if (pk_b64.empty()) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"missing public_key param\"}", "application/json");
                                                     //DBG("Missing public_key param");
                                                     return;
                                                 }

                                                 unsigned char nonce[NONCE_LEN];
                                                 if (RAND_bytes(nonce, NONCE_LEN) != 1) {
                                                     res.status = 500;
                                                     res.set_content("{\"error\":\"server error\"}", "application/json");
                                                     //DBG("RAND_bytes failed");
                                                     return;
                                                 }

                                                 std::string nonce_b64 = base64_urlsafe_no_pad(nonce, NONCE_LEN);
                                                 nonces.set(pk_b64, std::vector<unsigned char>(nonce, nonce + NONCE_LEN));

                                                 json body = { {"nonce", nonce_b64} };
                                                 res.set_content(body.dump(), "application/json");
                                                 //DBG("Sent nonce to client");
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /gdprAccepted – POST – requires pk, name, datetime, contact,    */
                                             /*                      client_pk, signature                           */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/gdprAccepted", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /gdprAccepted request");
                                                 try {
                                                     auto json_body = json::parse(req.body);

                                                     std::string pk_b64   = json_body.at("public_key");
                                                     std::string name     = json_body.at("name");
                                                     std::string datetime = json_body.at("datetime");
                                                     std::string contact  = json_body.at("contact");

                                                     std::string client_pk   = json_body.at("public_key");
                                                     std::string sig_b64     = json_body.at("signature");

                                                     std::vector<unsigned char> sig;
                                                     if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                         //DBG("Signature decode failed");
                                                         return;
                                                     }
                                                     sig.resize(256);
                                                     if (sig.size() != 256) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                         //DBG("Invalid signature length");
                                                         return;
                                                     }

                                                     // Verify signature of the nonce
                                                     if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                         res.status = 401;
                                                         res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                         //DBG("Signature verification failed");
                                                         return;
                                                     }

                                                     if(agreements.isRevoked(client_pk)){
                                                         res.status = 402;
                                                         res.set_content("{\"error\":\"previously revoked\"}", "application/json");
                                                         //DBG("Client previously revoked");
                                                         return;
                                                     }

                                                     // Store agreement
                                                     if (!agreements.addOrUpdate(pk_b64, name, datetime, contact)) {
                                                         res.status = 500;
                                                         res.set_content("{\"error\":\"failed to store agreement\"}", "application/json");
                                                         //DBG("Failed to store agreement");
                                                         return;
                                                     }

                                                     res.set_content("{\"ok\":true}", "application/json");
                                                     //DBG("GDPR agreement accepted and stored");
                                                 } catch (...) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON or missing fields\"}", "application/json");
                                                     //DBG("Invalid JSON or missing fields in /gdprAccepted");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /gdprDelete – POST – requires target_pk, client_pk, signature      */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/gdprDelete", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /gdprDelete request");
                                                 try {
                                                     auto json_body = json::parse(req.body);

                                                     std::string target_pk = json_body.at("public_key");          // key to delete
                                                     std::string client_pk = json_body.at("public_key");
                                                     std::string sig_b64   = json_body.at("signature");

                                                     std::vector<unsigned char> sig;
                                                     if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                         //DBG("Signature decode failed");
                                                         return;
                                                     }
                                                     sig.resize(256);
                                                     if (sig.size() != 256) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                         //DBG("Invalid signature length");
                                                         return;
                                                     }

                                                     // Verify signature of the nonce
                                                     if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                         res.status = 401;
                                                         res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                         //DBG("Signature verification failed");
                                                         return;
                                                     }

                                                     // Ensure client is authorized
                                                     if (!client_authorized(client_pk, agreements)) {
                                                         res.status = 403;
                                                         res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                         //DBG("Client not authorized for deletion");
                                                         return;
                                                     }

                                                     // Mark agreement as revoked (instead of erasing)
                                                     agreements.setRevoked(target_pk, true);

                                                     // Delete from other stores (optional – keeps audit trail)
                                                     kv.erase(target_pk);
                                                     bonds.erase(target_pk);
                                                     analysisBonds.erase(target_pk);
                                                     nonces.erase(target_pk);

                                                     res.set_content("{\"ok\":true}", "application/json");
                                                     //DBG("GDPR data deleted (revoked) for key " << target_pk);
                                                 } catch (...) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON or missing fields\"}", "application/json");
                                                     //DBG("Invalid JSON or missing fields in /gdprDelete");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /register – POST – authenticated, requires client_pk, signature   */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/register", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /register request");
                                                 try {
                                                     auto json_body = json::parse(req.body);

                                                     std::string pk_b64   = json_body.at("public_key");
                                                     std::string sig_b64  = json_body.at("signature");
                                                     std::string username = json_body.value("username", "");
                                                     std::string info     = json_body.value("info", "");

                                                     std::string client_pk   = json_body.at("public_key");
                                                     std::string client_sig_b64 = json_body.at("signature");

                                                     std::vector<unsigned char> client_sig;
                                                     if (!base64_urlsafe_no_pad_decode(client_sig_b64, client_sig)) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"client signature decode failed\"}", "application/json");
                                                         //DBG("Client signature decode failed");
                                                         return;
                                                     }
                                                     client_sig.resize(256);
                                                     if (client_sig.size() != 256) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"invalid client signature length\"}", "application/json");
                                                         //DBG("Invalid client signature length");
                                                         return;
                                                     }

                                                     // Verify client signature of nonce
                                                     if (!verify_and_consume_nonce(client_pk, client_sig, nonces)) {
                                                         res.status = 401;
                                                         res.set_content("{\"error\":\"client signature verification failed\"}", "application/json");
                                                         //DBG("Client signature verification failed");
                                                         return;
                                                     }

                                                     // Ensure client is authorized (exists in agreements)
                                                     if (!client_authorized(client_pk, agreements)) {
                                                         res.status = 403;
                                                         res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                         //DBG("Client not authorized for registration");
                                                         return;
                                                     }

                                                     // Register key
                                                     if (!kv.addOrUpdate(pk_b64, username, info)) {
                                                         res.status = 500;
                                                         res.set_content("{\"error\":\"store full\"}", "application/json");
                                                         //DBG("KVStore full");
                                                         return;
                                                     }

                                                     /* Optional: client can send bonds in the same request */
                                                     if (json_body.contains("bonds") && json_body["bonds"].is_array()) {
                                                         for (auto& b : json_body["bonds"]) {
                                                             if (b.is_string()) bonds.add(pk_b64, b.get<std::string>());
                                                         }
                                                     }

                                                     res.set_content("{\"ok\":true}", "application/json");
                                                     //DBG("Registered key " << pk_b64);
                                                 } catch (...) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON\"}", "application/json");
                                                     //DBG("Invalid JSON in /register");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /lookup – GET – authenticated, requires client_pk, signature    */
                                             /* ------------------------------------------------------------------ */
                                             svr.Get("/lookup", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /lookup request");
                                                 std::string pk_b64 = req.get_param_value("target_public_key");
                                                 std::string client_pk = req.get_param_value("public_key");
                                                 std::string sig_b64 = req.get_param_value("signature");

                                                 //std::cout << "target public key: " << pk_b64 << std::endl;
                                                 //std::cout << "public key: " << pk_b64 << std::endl;
                                                 //std::cout << "signature: " << pk_b64 << std::endl;

                                                 if (pk_b64.empty() || client_pk.empty() || sig_b64.empty()) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"missing public_key, client_public_key or client_signature\"}", "application/json");
                                                     //DBG("Missing parameters in /lookup");
                                                     return;
                                                 }

                                                 std::vector<unsigned char> sig;
                                                 if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                     //DBG("Signature decode failed in /lookup");
                                                     return;
                                                 }
                                                 sig.resize(256);
                                                 if (sig.size() != 256) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                     //DBG("Invalid signature length in /lookup");
                                                     return;
                                                 }

                                                 if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                     res.status = 401;
                                                     res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                     //DBG("Signature verification failed in /lookup");
                                                     return;
                                                 }

                                                 if (!client_authorized(client_pk, agreements)) {
                                                     res.status = 403;
                                                     res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                     //DBG("Client not authorized in /lookup");
                                                     return;
                                                 }

                                                 auto meta_opt = kv.lookup(pk_b64);
                                                 if (!meta_opt.has_value()) {
                                                     res.status = 404;
                                                     res.set_content("{\"error\":\"not found\"}", "application/json");
                                                     //DBG("KVStore lookup miss for key " << pk_b64);
                                                     return;
                                                 }


                                                 //std::cout << "username: " << meta_opt->username << std::endl;
                                                 //std::cout << "signature: " << meta_opt->info << std::endl;

                                                 json body = {
                                                     {"username", meta_opt->username},
                                                     {"info", meta_opt->info}
                                                 };
                                                 res.set_content(body.dump(), "application/json");
                                                 //DBG("Returned lookup result for key " << pk_b64);
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /bonds – GET (retrieve & keep until /clearBonds)                 */
                                             /* ------------------------------------------------------------------ */
                                             svr.Get("/bonds", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /bonds request");
                                                 std::string pk_b64 = req.get_param_value("public_key");
                                                 std::string client_pk = req.get_param_value("public_key");
                                                 std::string sig_b64 = req.get_param_value("signature");

                                                 if (pk_b64.empty() || client_pk.empty() || sig_b64.empty()) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"missing public_key, client_public_key or client_signature\"}", "application/json");
                                                     //DBG("Missing parameters in /bonds");
                                                     return;
                                                 }

                                                 std::vector<unsigned char> sig;
                                                 if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                     //DBG("Signature decode failed in /bonds");
                                                     return;
                                                 }
                                                 sig.resize(256);
                                                 if (sig.size() != 256) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                     //DBG("Invalid signature length in /bonds");
                                                     return;
                                                 }

                                                 if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                     res.status = 401;
                                                     res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                     //DBG("Signature verification failed in /bonds");
                                                     return;
                                                 }

                                                 if (!client_authorized(client_pk, agreements)) {
                                                     res.status = 403;
                                                     res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                     //DBG("Client not authorized in /bonds");
                                                     return;
                                                 }

                                                 auto bonds_vec = bonds.consume(pk_b64);
                                                 if (bonds_vec.empty()) {
                                                     res.status = 404;
                                                     res.set_content("{\"error\":\"no bonds\"}", "application/json");
                                                     //DBG("No bonds found for key " << pk_b64);
                                                     return;
                                                 }

                                                 json body = json::array();
                                                 for (auto& b : bonds_vec) body.push_back(b);
                                                 res.set_content(body.dump(), "application/json");
                                                 //DBG("Returned " << bonds_vec.size() << " bonds for key " << pk_b64);
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /createBond – POST – authenticated, requires client_pk, signature   */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/createBond", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /createBond request");
                                                 //std::cout << req.body << std::endl;
                                                 try {
                                                     auto json_body = json::parse(req.body);
                                                     std::string pk_b64 = json_body.at("target_public_key");
                                                     //std::cout << "target public key: " << pk_b64 << std::endl << std::endl;
                                                     std::string bond   = json_body.at("bond");
                                                     //std::cout << "bond: " << bond << std::endl << std::endl;

                                                     std::string client_pk   = json_body.at("public_key");
                                                     //std::cout << "public key: " << client_pk << std::endl << std::endl;
                                                     std::string sig_b64     = json_body.at("signature");


                                                     //std::cout << "signature: " << sig_b64 << std::endl << std::endl;

                                                     std::vector<unsigned char> sig;
                                                     if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                         //DBG("Signature decode failed");
                                                         return;
                                                     }
                                                     sig.resize(256);
                                                     if (sig.size() != 256) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                         //DBG("Invalid signature length");
                                                         return;
                                                     }

                                                     if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                         res.status = 401;
                                                         res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                         //DBG("Signature verification failed");
                                                         return;
                                                     }

                                                     if (!client_authorized(client_pk, agreements)) {
                                                         res.status = 403;
                                                         res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                         //DBG("Client not authorized for bond creation");
                                                         return;
                                                     }

                                                     bonds.add(pk_b64, bond);
                                                     res.set_content("{\"ok\":true}", "application/json");
                                                     //DBG("Bond added for key " << pk_b64);
                                                 } catch (...) {

                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON or missing fields\"}", "application/json");
                                                     //DBG("Invalid JSON or missing fields in /createBond");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /setAnalysisBonds – POST – authenticated, requires client_pk,     */
                                             /*                           signature                                       */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/setAnalysisBonds", [&](const httplib::Request& req, httplib::Response& res) {
                                                 //DBG("Received /setAnalysisBonds request");
                                                 try {
                                                     auto json_body = json::parse(req.body);

                                                     std::string pk_b64  = json_body.at("public_key");
                                                     std::string client_pk = json_body.at("public_key");
                                                     std::string sig_b64 = json_body.at("signature");

                                                     if (!json_body.contains("analysis_bonds") ||
                                                         !json_body["analysis_bonds"].is_array()) {
                                                         res.status = 400;
                                                     res.set_content("{\"error\":\"missing or invalid analysis_bonds array\"}",
                                                                     "application/json");
                                                     //DBG("Missing/invalid analysis_bonds array");
                                                     return;
                                                         }

                                                         std::vector<unsigned char> sig;
                                                         if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                             res.status = 400;
                                                             res.set_content("{\"error\":\"invalid signature\"}", "application/json");
                                                             //DBG("Signature decode failed");
                                                             return;
                                                         }

                                                         sig.resize(256);

                                                         if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                             res.status = 401;
                                                             res.set_content("{\"error\":\"signature verification failed\"}",
                                                                             "application/json");
                                                             //DBG("Signature verification failed");
                                                             return;
                                                         }

                                                         if (!client_authorized(client_pk, agreements)) {
                                                             res.status = 403;
                                                             res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                             //DBG("Client not authorized for analysis bonds");
                                                             return;
                                                         }

                                                         // Filter out bonds that reference revoked keys
                                                         std::vector<std::string> filtered_bonds;
                                                         for (auto& b : json_body["analysis_bonds"]) {
                                                             if (!b.is_string()) {
                                                                 res.status = 400;
                                                                 res.set_content("{\"error\":\"analysis_bonds must be an array of strings\"}",
                                                                                 "application/json");
                                                                 //DBG("analysis_bonds contains non‑string");
                                                                 return;
                                                             }
                                                             std::string bond_json = b.get<std::string>();

                                                             // Parse the bond JSON to inspect sender/receiver
                                                             try {
                                                                 json bond_obj = json::parse(bond_json);
                                                                 std::string sender = bond_obj.value("sender", "");
                                                                 std::string receiver = bond_obj.value("receiver", "");

                                                                 // Skip bond if any party is revoked
                                                                 if (agreements.isRevoked(sender) || agreements.isRevoked(receiver)) {
                                                                     //DBG("Skipping bond with revoked party: sender=" << sender << ", receiver=" << receiver);
                                                                     continue;   // do not include
                                                                 }
                                                                 filtered_bonds.push_back(bond_json);
                                                             } catch (...) {
                                                                 // If bond is malformed, skip it
                                                                 //DBG("Malformed bond JSON – skipping");
                                                                 continue;
                                                             }
                                                         }

                                                         analysisBonds.set(pk_b64, filtered_bonds);
                                                         res.set_content("{\"ok\":true}", "application/json");
                                                         //DBG("Set analysis bonds for key " << pk_b64);
                                                 } catch (const json::exception&) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON\"}", "application/json");
                                                     //DBG("Invalid JSON in /setAnalysisBonds");
                                                 } catch (const std::exception&) {
                                                     res.status = 500;
                                                     res.set_content("{\"error\":\"internal server error\"}", "application/json");
                                                     //DBG("Unhandled exception in /setAnalysisBonds");
                                                 } catch (...) {
                                                     res.status = 500;
                                                     res.set_content("{\"error\":\"internal server error\"}", "application/json");
                                                     //DBG("Unknown error in /setAnalysisBonds");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  /getAnalysisBonds – GET – public read (no auth)                  */
                                             /* ------------------------------------------------------------------ */
                                             svr.Post("/getAnalysisBonds", [&](const httplib::Request& req, httplib::Response& res) {

                                                 //DBG("Received /getAnalysisBonds request");
                                                 try {
                                                     auto json_body = json::parse(req.body);
                                                     std::string pk_b64 = req.get_param_value("target_public_key");
                                                     std::string client_pk   = json_body.at("public_key");
                                                     std::string sig_b64     = json_body.at("signature");

                                                     if (pk_b64.empty()) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"missing public_key param\"}", "application/json");
                                                         //DBG("Missing public_key param");
                                                         return;
                                                     }

                                                     std::vector<unsigned char> sig;
                                                     if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                         //DBG("Signature decode failed");
                                                         return;
                                                     }
                                                     sig.resize(256);
                                                     if (sig.size() != 256) {
                                                         res.status = 400;
                                                         res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                         //DBG("Invalid signature length");
                                                         return;
                                                     }

                                                     if (!verify_and_consume_nonce(client_pk, sig, nonces)) {
                                                         res.status = 401;
                                                         res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                         //DBG("Signature verification failed");
                                                         return;
                                                     }

                                                     if (!client_authorized(client_pk, agreements)) {
                                                         res.status = 403;
                                                         res.set_content("{\"error\":\"client not authorized\"}", "application/json");
                                                         //DBG("Client not authorized for analysis bond retrieval");
                                                         return;
                                                     }

                                                     auto bonds_vec = analysisBonds.get(pk_b64);
                                                     if (bonds_vec.empty()) {
                                                         res.status = 404;
                                                         res.set_content("{\"error\":\"no analysis bonds found\"}", "application/json");
                                                         //DBG("No analysis bonds found for key " << pk_b64);
                                                         return;
                                                     }

                                                     json body = json::array();
                                                     for (auto& b : bonds_vec) body.push_back(b);
                                                     res.set_content(body.dump(), "application/json");
                                                     //DBG("Returned analysis bonds for key " << pk_b64);
                                                 } catch (...) {
                                                     res.status = 400;
                                                     res.set_content("{\"error\":\"invalid JSON or missing fields\"}", "application/json");
                                                     //DBG("Invalid JSON or missing fields in /getAnalysisBonds");
                                                 }
                                             });

                                             /* ------------------------------------------------------------------ */
                                             /*  Server listen                                                    */
                                             /* ------------------------------------------------------------------ */
                                             svr.listen(host.c_str(), port);

                                             return 0;
                                         }
