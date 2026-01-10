/*********************************************************************
 *  rsa2048_server.cpp  –  cpp‑httplib + OpenSSL
 *
 *  The server now also stores a per‑key “username” and “info” strings.
 *  All key‑metadata is persisted to a local JSON file and re‑loaded
 *  on startup.  It also supports bonds and a public‑key‑agnostic
 *  lookup endpoint, and a nonce that is automatically reset after
 *  each request that uses it.
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
#include <optional>                       // <--- new

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "httplib.h"                 // single‑header HTTP server
#include "nlohmann/json.hpp"          // nlohmann/json (single header)

#include <fstream>

#include <string_view>

using json = nlohmann::json;

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
    int decoded = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(tmp.data()), tmp.size());
    if (decoded < 0) return false;
    out.resize(decoded);
    return true;
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  Helper – hex dump (debug only)                                      */
                                         /* --------------------------------------------------------------------- */
                                         static std::string hex_dump(const std::vector<unsigned char>& v) {
                                             std::ostringstream ss;
                                             ss << std::hex << std::setfill('0');
                                             for (unsigned char c : v) ss << std::setw(2) << static_cast<int>(c);
                                             return ss.str();
                                         }

                                         /* --------------------------------------------------------------------- */
                                         /*  RSA key handling                                                    */
                                         /* --------------------------------------------------------------------- */
                                         class RSAKeyPair
                                         {
                                         public:
                                             RSAKeyPair() : rsa_(nullptr) {}
                                             ~RSAKeyPair() { if (rsa_) RSA_free(rsa_); }

                                             /* load from PEM file (private key) */
                                             bool loadPEM(const std::string& path)
                                             {
                                                 FILE* fp = fopen(path.c_str(), "rb");
                                                 if (!fp) { perror("fopen"); return false; }
                                                 RSA* r = PEM_read_RSAPrivateKey(fp, nullptr, nullptr, nullptr);
                                                 fclose(fp);
                                                 if (!r) { printErr("PEM_read_RSAPrivateKey"); return false; }
                                                 rsa_ = r;
                                                 return true;
                                             }

                                             /* write private key to PEM file */
                                             bool writePEM(const std::string& path) const
                                             {
                                                 FILE* fp = fopen(path.c_str(), "wb");
                                                 if (!fp) { perror("fopen"); return false; }
                                                 int ok = PEM_write_RSAPrivateKey(fp, rsa_, nullptr, nullptr, 0, nullptr, nullptr);
                                                 fclose(fp);
                                                 if (!ok) { printErr("PEM_write_RSAPrivateKey"); return false; }
                                                 return true;
                                             }

                                             /* generate a new 2048‑bit key */
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
                                                 return true;
                                             }

                                             /* DER‑encoded, base64‑url‑safe public key */
                                             std::string publicKeyB64() const
                                             {
                                                 if (!rsa_) return "";
                                                 int len = i2d_RSA_PUBKEY(rsa_, nullptr);
                                                 std::vector<unsigned char> buf(len);
                                                 unsigned char* p = buf.data();
                                                 i2d_RSA_PUBKEY(rsa_, &p);
                                                 return base64_urlsafe_no_pad(buf.data(), buf.size());
                                             }

                                             /* Sign data with SHA‑256 */
                                             std::vector<unsigned char> sign(const std::vector<unsigned char>& data) const
                                             {
                                                 std::vector<unsigned char> sig(RSA_size(rsa_));
                                                 unsigned int siglen;
                                                 if (RSA_sign(NID_sha256, data.data(), static_cast<int>(data.size()),
                                                     sig.data(), &siglen, rsa_) != 1) {
                                                     printErr("RSA_sign");
                                                 return {};
                                                     }
                                                     sig.resize(siglen);
                                                     return sig;
                                             }

                                         private:
                                             void printErr(const char* msg) const
                                             {
                                                 unsigned long err = ERR_get_error();
                                                 char buf[256];
                                                 ERR_error_string_n(err, buf, sizeof(buf));
                                                 //std::cerr << msg << ": " << buf << std::endl;
                                             }

                                             RSA* rsa_;
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  In‑memory key ↔ IP store + username & info, persisted to file      */
                                         /* --------------------------------------------------------------------- */
                                         class KVStore {
                                         public:
                                             struct Meta {
                                                 std::string ip;
                                                 std::string username;
                                                 std::string info;
                                             };

                                             explicit KVStore(const std::string& file_path) : file_path_(file_path) {
                                                 loadFromFile(file_path_);
                                             }

                                             /* Add or update a key entry.  Returns false if store full. */
                                             bool addOrUpdate(const std::string& pk,
                                                              const std::string& ip,
                                                              const std::string& username = "",
                                                              const std::string& info = "") {
                                                 //std::lock_guard<std::mutex> lk(m_);

                                                 store_[pk] = {ip, username, info};
                                                 //std::cout << "[KVStore] addOrUpdate(): key " << pk << " stored/updated\n";
                                                 return saveToFile(file_path_);   // persist after every change
                                                              }

                                                              /* Retrieve a key entry.  Returns std::nullopt if not found. */
                                                              std::optional<Meta> lookup(const std::string& pk) const {
                                                                  //std::cout << "debug 4" << std::endl;
                                                                  //std::lock_guard<std::mutex> lk(m_);
                                                                  //std::cout << "debug 5" << std::endl;
                                                                  auto it = store_.find(pk);
                                                                  //std::cout << "debug 6" << std::endl;
                                                                  if (it == store_.end()) {
                                                                      //std::cout << "[KVStore] lookup(): key " << pk << " not found\n";
                                                                      return std::nullopt;
                                                                  }
                                                                  //std::cout << "[KVStore] lookup(): key " << pk << " found → ip " << it->second.ip << "\n";
                                                                  return it->second;
                                                              }

                                         private:
                                             std::unordered_map<std::string, Meta> store_;
                                             //mutable std::mutex m_;
                                             std::string file_path_;

                                             /* Load from JSON file.  Returns true on success. */
                                             bool loadFromFile(const std::string& filename) {
                                                 std::ifstream ifs(filename);
                                                 if (!ifs.is_open()) {
                                                     //std::cout << "[KVStore] loadFromFile(): file " << filename << " not found – starting fresh\n";
                                                     return true;
                                                 }
                                                 try {
                                                     json j;
                                                     ifs >> j;
                                                     //std::lock_guard<std::mutex> lk(m_);
                                                     for (auto& [key, val] : j.items()) {
                                                         Meta m;
                                                         m.ip        = val.value("ip", "");
                                                         m.username  = val.value("username", "");
                                                         m.info      = val.value("info", "");
                                                         store_[key] = m;
                                                     }
                                                     //std::cout << "[KVStore] loadFromFile(): loaded " << store_.size() << " entries\n";
                                                 } catch (const std::exception& e) {
                                                     //std::cerr << "[KVStore] loadFromFile() exception: " << e.what() << "\n";
                                                     return false;
                                                 }
                                                 return true;
                                             }

                                             /* Persist to JSON file.  Returns true on success. */
                                             bool saveToFile(const std::string& filename) const {
                                                 std::ofstream ofs(filename);
                                                 if (!ofs.is_open()) {
                                                     //std::cerr << "[KVStore] saveToFile(): could not open " << filename << "\n";
                                                     return false;
                                                 }
                                                 try {
                                                     json j;
                                                     //std::lock_guard<std::mutex> lk(m_);
                                                     for (const auto& [key, meta] : store_) {
                                                         j[key] = { {"ip", meta.ip},
                                                         {"username", meta.username},
                                                         {"info", meta.info} };
                                                     }
                                                     ofs << std::setw(4) << j << '\n';
                                                 } catch (const std::exception& e) {
                                                     //std::cerr << "[KVStore] saveToFile() exception: " << e.what() << "\n";
                                                     return false;
                                                 }
                                                 return true;
                                             }
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Bonds buffer – one per public key                                    */
                                         /* --------------------------------------------------------------------- */
                                         class BondsStore {
                                         public:
                                             bool add(const std::string& pk, const std::string& bond_json) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 buffer_[pk].push_back(bond_json);
                                                 //std::cout << "[BondsStore] add(): bond added for key " << pk << "\n";
                                                 return true;
                                             }

                                             std::vector<std::string> consume(const std::string& pk) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 auto it = buffer_.find(pk);
                                                 if (it == buffer_.end()) return {};
                                                 auto vec = std::move(it->second);
                                                 buffer_.erase(it);
                                                 //std::cout << "[BondsStore] consume(): buffer cleared for key " << pk << "\n";
                                                 return vec;
                                             }

                                             void clear(const std::string& pk) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 buffer_.erase(pk);
                                                 //std::cout << "[BondsStore] clear(): buffer erased for key " << pk << "\n";
                                             }

                                         private:
                                             //std::mutex m_;
                                             std::unordered_map<std::string, std::vector<std::string>> buffer_;
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  Nonce store – one per public key                                     */
                                         /* --------------------------------------------------------------------- */
                                         class NonceStore {
                                         public:
                                             bool set(const std::string& pk, const std::vector<unsigned char>& nonce) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 nonce_[pk] = nonce;
                                                 //std::cout << "[NonceStore] set(): nonce stored for key " << pk << "\n";
                                                 return true;
                                             }

                                             std::vector<unsigned char> get(const std::string& pk) const {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 auto it = nonce_.find(pk);
                                                 if (it == nonce_.end()) {
                                                     //std::cout << "[NonceStore] get(): nonce not found for key " << pk << "\n";
                                                     return {};
                                                 }
                                                 //std::cout << "[NonceStore] get(): nonce retrieved for key " << pk << "\n";
                                                 //std::cout << "[NonceStore] get(): nonce : " << hex_dump((*it).second) << "\n";
                                                 return it->second;
                                             }

                                             void erase(const std::string& pk) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 nonce_.erase(pk);
                                                 //std::cout << "[NonceStore] erase(): nonce cleared for key " << pk << "\n";
                                             }

                                         private:
                                             //mutable std::mutex m_;
                                             std::unordered_map<std::string, std::vector<unsigned char>> nonce_;
                                         };

                                         class ConnectionRequestStore {
                                         public:
                                             /* Store the requestor key for the given target key.
                                              *     Replaces any existing value. */
                                             bool store(const std::string& target_pk,
                                                        const std::string& requestor_pk) {
                                                 //std::lock_guard<std::mutex> lk(m_);
                                                 conn_[target_pk] = requestor_pk;
                                                 //std::cout << "[ConnectionRequestStore] stored request from " << requestor_pk << " for target " << target_pk << "\n";
                                                 return true;
                                                        }

                                                        /* Consume (retrieve & delete) the requestor key for the target key.
                                                         *     Returns std::nullopt if none. */
                                                        std::optional<std::string> consume(const std::string& target_pk) {
                                                            //std::lock_guard<std::mutex> lk(m_);
                                                            auto it = conn_.find(target_pk);
                                                            if (it == conn_.end()) {
                                                                //std::cout << "[ConnectionRequestStore] no request for "<< target_pk << "\n";
                                                                return std::nullopt;
                                                            }
                                                            std::string req = std::move(it->second);
                                                            conn_.erase(it);
                                                            //std::cout << "[ConnectionRequestStore] consumed request for "<< target_pk << "\n";
                                                            return req;
                                                        }

                                         private:
                                             //mutable std::mutex m_;
                                             std::unordered_map<std::string, std::string> conn_;
                                         };

                                         /* --------------------------------------------------------------------- */
                                         /*  RSA verification helper                                              */
                                         /* --------------------------------------------------------------------- */
                                         static bool verify_signature(const std::string& pk_b64,
                                                                      const std::vector<unsigned char>& msg,
                                                                      const std::vector<unsigned char>& sig) {
                                             std::vector<unsigned char> pk_der;
                                             if (!base64_urlsafe_no_pad_decode(pk_b64, pk_der)) {
                                                 //std::cerr << "[verify] Failed to decode public key\n";
                                                 return false;
                                             }

                                             const unsigned char* p = pk_der.data();
                                             RSA* rsa = d2i_RSA_PUBKEY(nullptr, &p, pk_der.size());
                                             if (!rsa) {
                                                 //std::cerr << "[verify] d2i_RSA_PUBKEY failed\n";
                                                 return false;
                                             }

                                             EVP_PKEY* evp_pub = EVP_PKEY_new();
                                             EVP_PKEY_assign_RSA(evp_pub, rsa);    // rsa is now owned by evp_pub

                                             EVP_MD_CTX* ctx = EVP_MD_CTX_new();
                                             if (!ctx) {
                                                 EVP_PKEY_free(evp_pub);
                                                 //std::cerr << "[verify] EVP_MD_CTX_new failed\n";
                                                 return false;
                                             }

                                             bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, evp_pub) == 1 &&
                                             EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) == 1 &&
                                             EVP_DigestVerifyFinal(ctx, sig.data(), sig.size()) == 1;

                                             EVP_MD_CTX_free(ctx);
                                             EVP_PKEY_free(evp_pub);

                                             if (!ok){
                                                 //std::cerr << "[verify] Signature verification failed\n";
                                                 //std::cerr << "[verify] public key:" << pk_b64 << "\n";
                                                 //std::cerr << "[verify] public key in hex:" << hex_dump(pk_der) << "\n";
                                                 //std::cerr << "[verify] nonce:" << hex_dump(msg)<< "\n";
                                                 //std::cerr << "[verify] signature:" << hex_dump(sig) << "\n";
                                             }
                                             else
                                                 //std::cout << "[verify] Signature verified successfully\n";
                                             return ok;
                                                                      }

                                                                      /* --------------------------------------------------------------------- */
                                                                      /*  Helper – verify signature against stored nonce for a public key      */
                                                                      /* --------------------------------------------------------------------- */
                                                                      static bool verify_and_consume_nonce(const std::string& pk_b64,
                                                                                                           const std::vector<unsigned char>& sig,
                                                                                                           NonceStore& ns) {
                                                                          auto nonce = ns.get(pk_b64);
                                                                          if (nonce.empty()) {
                                                                              //std::cerr << "[auth] No nonce stored for key " << pk_b64 << "\n";
                                                                              return false;
                                                                          }

                                                                          if (!verify_signature(pk_b64, nonce, sig))
                                                                              return false;

                                                                          // Reset nonce after successful use
                                                                          ns.erase(pk_b64);
                                                                          return true;
                                                                                                           }

                                                                                                           /* --------------------------------------------------------------------- */
                                                                                                           /*  Main entry point                                                     */
                                                                                                           /* --------------------------------------------------------------------- */
                                                                                                           int main() {
                                                                                                               //std::cout << "[Main] Starting RSA‑2048 registration server\n";

                                                                                                               /* Initialise OpenSSL */
                                                                                                               OpenSSL_add_all_algorithms();
                                                                                                               ERR_load_BIO_strings();
                                                                                                               ERR_load_crypto_strings();

                                                                                                               const char* KV_FILE = "kvstore.json";
                                                                                                               KVStore kv(KV_FILE);
                                                                                                               BondsStore bonds;
                                                                                                               NonceStore nonces;
                                                                                                               ConnectionRequestStore connStore;
                                                                                                               constexpr size_t NONCE_LEN = 32;

                                                                                                               httplib::Server svr;

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /challenge – GET – requires public_key param                    */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Get("/challenge", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/challenge] GET request received\n";

                                                                                                                   std::string pk_b64 = req.get_param_value("public_key");
                                                                                                                   if (pk_b64.empty()) {
                                                                                                                       //std::cerr << "[/challenge] Missing public_key parameter\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"missing public_key param\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }
                                                                                                                   //std::cout << "[/challenge] public_key (b64): " << pk_b64 << "\n";

                                                                                                                   unsigned char nonce[NONCE_LEN];
                                                                                                                   if (RAND_bytes(nonce, NONCE_LEN) != 1) {
                                                                                                                       //std::cerr << "[/challenge] RAND_bytes failed\n";
                                                                                                                       res.status = 500;
                                                                                                                       res.set_content("{\"error\":\"server error\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   std::string nonce_b64 = base64_urlsafe_no_pad(nonce, NONCE_LEN);

                                                                                                                   //std::cout << "[/challenge] Nonce base64: " << nonce_b64 << "\n";

                                                                                                                   nonces.set(pk_b64, std::vector<unsigned char>(nonce, nonce + NONCE_LEN));

                                                                                                                   json body = { {"nonce", nonce_b64} };
                                                                                                                   res.set_content(body.dump(), "application/json");
                                                                                                                   //std::cout << "[/challenge] Response sent\n";
                                                                                                               });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /register – POST – requires pk, ip, signature                    */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Post("/register", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/register] POST request received\n";
                                                                                                                   try {
                                                                                                                       auto json_body = json::parse(req.body);

                                                                                                                       //std::cout << json_body.dump() << std::endl;

                                                                                                                       std::string pk_b64   = json_body.at("public_key");
                                                                                                                       std::string ip_str   = json_body.at("ip");
                                                                                                                       std::string sig_b64  = json_body.at("signature");

                                                                                                                       /* Optional fields */
                                                                                                                       std::string username = json_body["username"];
                                                                                                                       std::string info     = json_body["info"];


                                                                                                                       //std::cout << "[/register] Extracted fields:\n";
                                                                                                                       //std::cout << "  public_key : " << pk_b64 << "\n";
                                                                                                                       //std::cout << "  ip         : " << ip_str << "\n";
                                                                                                                       //std::cout << "  signature  : " << sig_b64 << "\n";
                                                                                                                       //std::cout << "  username   : " << username << "\n";
                                                                                                                       //std::cout << "  info       : " << info << "\n";

                                                                                                                       std::vector<unsigned char> sig;
                                                                                                                       if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                                                                                           //std::cerr << "[/register] Signature base64 decode failed\n";
                                                                                                                           res.status = 400;
                                                                                                                           res.set_content("{\"error\":\"signature decode failed\"}", "application/json");
                                                                                                                           return;
                                                                                                                       }

                                                                                                                       sig.resize(256);
                                                                                                                       if (sig.size() != 256) {
                                                                                                                           //std::cerr << "[/register] Invalid signature length\n";
                                                                                                                           res.status = 400;
                                                                                                                           res.set_content("{\"error\":\"invalid signature length\"}", "application/json");
                                                                                                                           return;
                                                                                                                       }

                                                                                                                       /* Verify against the stored nonce – this also erases the nonce */
                                                                                                                       if (!verify_and_consume_nonce(pk_b64, sig, nonces)) {
                                                                                                                           res.status = 401;
                                                                                                                           //std::cerr << "sig: " << hex_dump(sig) << std::endl;
                                                                                                                           res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                                                                                           return;
                                                                                                                       }

                                                                                                                       /* Store the key–IP mapping along with username & info */
                                                                                                                       if (!kv.addOrUpdate(pk_b64, ip_str, username, info)) {
                                                                                                                           res.status = 500;
                                                                                                                           res.set_content("{\"error\":\"store full\"}", "application/json");
                                                                                                                           return;
                                                                                                                       }

                                                                                                                       /* Optional: client can send bonds in the same request */
                                                                                                                       if (json_body.contains("bonds") && json_body["bonds"].is_array()) {
                                                                                                                           for (auto& b : json_body["bonds"]) {
                                                                                                                               if (b.is_string()) bonds.add(pk_b64, b.get<std::string>());
                                                                                                                           }
                                                                                                                       }

                                                                                                                       //std::cout << "[/register] Registration succeeded for IP " << ip_str << "\n";
                                                                                                                       res.set_content("{\"ok\":true}", "application/json");
                                                                                                                   } catch (const std::exception& e) {
                                                                                                                       //std::cerr << "[/register] Exception: " << e.what() << "\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"invalid JSON\"}", "application/json");
                                                                                                                   }
                                                                                                               });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /lookup – GET – anyone can look up a public key (no auth)         */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Get("/lookup", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/lookup] GET request received\n";

                                                                                                                   std::string pk_b64 = req.get_param_value("public_key");

                                                                                                                   //std::cerr <<" debug1" << std::endl;

                                                                                                                   if (pk_b64.empty()) {
                                                                                                                       //std::cerr << "[/lookup] Missing public_key parameter\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"missing public_key\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                    //std::cerr <<" debug2" << std::endl;


                                                                                                                   auto meta_opt = kv.lookup(pk_b64);

                                                                                                                    //std::cerr <<" debug3" << std::endl;

                                                                                                                   if (!meta_opt.has_value()) {
                                                                                                                       //std::cerr << "[/lookup] No entry found for given public key\n";
                                                                                                                       res.status = 404;
                                                                                                                       res.set_content("{\"error\":\"not found\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   //std::cerr <<" debug" << std::endl;

                                                                                                                   json body = {
                                                                                                                       {"ip", meta_opt->ip},
                                                                                                                       {"username", meta_opt->username},
                                                                                                                       {"info", meta_opt->info}
                                                                                                                   };
                                                                                                                   //std::cerr << "returned " << body.dump() << std::endl;
                                                                                                                   res.set_content(body.dump(), "application/json");
                                                                                                               });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /bonds – GET (retrieve & keep until /clearBonds)                */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Get("/bonds", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/bonds] GET request received\n";

                                                                                                                   std::string pk_b64 = req.get_param_value("public_key");
                                                                                                                   std::string sig_b64 = req.get_param_value("signature");

                                                                                                                   //std::cout << "public key requesting its bonds: " << pk_b64 << std::endl;
                                                                                                                   //std::cout << "signature: " << sig_b64 << std::endl;

                                                                                                                   if (pk_b64.empty() || sig_b64.empty()) {
                                                                                                                       //std::cerr << "[/bonds] Missing parameters\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"missing public_key or signature\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   std::vector<unsigned char> sig;
                                                                                                                   if (!base64_urlsafe_no_pad_decode(sig_b64, sig)) {
                                                                                                                       //std::cerr << "[/bonds] Invalid signature\n";

                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"invalid signature\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }
                                                                                                                   if (sig.size() != 256)
                                                                                                                   {
                                                                                                                       //std::cerr << "[/bonds] sig size " << sig.size() << "\n";
                                                                                                                       //std::cerr << "hex of sig: " << hex_dump(sig) << std::endl;
                                                                                                                       sig.resize(256);
                                                                                                                   }

                                                                                                                   /* Verify signature – also erases nonce */
                                                                                                                   if (!verify_and_consume_nonce(pk_b64, sig, nonces)) {
                                                                                                                       res.status = 401;
                                                                                                                       res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   std::vector<std::string> bonds_vec = bonds.consume(pk_b64);
                                                                                                                   if (bonds_vec.empty()) {
                                                                                                                       //std::cerr << "[/bonds] No bonds available for key " << pk_b64 << "\n";
                                                                                                                       res.status = 404;
                                                                                                                       res.set_content("{\"error\":\"no bonds\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   json body = json::array();
                                                                                                                   for (auto& b : bonds_vec) body.push_back(b);
                                                                                                                   res.set_content(body.dump(), "application/json");
                                                                                                                   //std::cout << "[/bonds] Sent " << bonds_vec.size() << " bonds for key " << pk_b64 << "\n";
                                                                                                               });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /clearBonds – GET – clears the bonds buffer for a key            */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Get("/clearBonds", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/clearBonds] GET request received\n";

                                                                                                                   std::string pk_b64 = req.get_param_value("public_key");
                                                                                                                   std::string sig_b64 = req.get_param_value("signature");

                                                                                                                   if (pk_b64.empty() || sig_b64.empty()) {
                                                                                                                       //std::cerr << "[/clearBonds] Missing parameters\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"missing public_key or signature\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   std::vector<unsigned char> sig;
                                                                                                                   if (!base64_urlsafe_no_pad_decode(sig_b64, sig) || sig.size() != 256) {
                                                                                                                       //std::cerr << "[/clearBonds] Invalid signature\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"invalid signature\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   if (!verify_and_consume_nonce(pk_b64, sig, nonces)) {
                                                                                                                       res.status = 401;
                                                                                                                       res.set_content("{\"error\":\"signature verification failed\"}", "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   bonds.clear(pk_b64);
                                                                                                                   res.set_content("{\"ok\":true}", "application/json");
                                                                                                                   //std::cout << "[/clearBonds] Cleared bonds for key " << pk_b64 << "\n";
                                                                                                               });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /createBond – POST – anyone can add a bond to a public key      */
                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               svr.Post("/createBond", [&](const httplib::Request& req, httplib::Response& res) {
                                                                                                                   //std::cout << "[/createBond] POST request received\n";
                                                                                                                   try {
                                                                                                                       auto json_body = json::parse(req.body);

                                                                                                                       std::string pk_b64 = json_body.at("public_key");
                                                                                                                       std::string bond   = json_body.at("bond");   // bond JSON string (or any payload)

                                                                                                               bonds.add(pk_b64, bond);
                                                                                                               //std::cout << "[/createBond] Bond added for key " << pk_b64 << "\n";
                                                                                                               res.set_content("{\"ok\":true}", "application/json");
                                                                                                                   } catch (const std::exception& e) {
                                                                                                                       //std::cerr << "[/createBond] Exception: " << e.what() << "\n";
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"invalid JSON\"}", "application/json");
                                                                                                                   }
                                                                                                               });

                                                                                                               /*  /storeConnectionRequest – POST – store a pending request          */
                                                                                                               svr.Post("/storeConnectionRequest", [&](const httplib::Request& req,
                                                                                                                                                       httplib::Response& res) {
                                                                                                                   //std::cout << "[/storeConnectionRequest] POST request received\n";
                                                                                                                   try {
                                                                                                                       auto json_body = json::parse(req.body);

                                                                                                                       std::string target_pk = json_body.at("target_public_key");
                                                                                                                       std::string requestor_pk = json_body.at("requester_public_key");

                                                                                                                       connStore.store(target_pk, requestor_pk);

                                                                                                                       res.set_content("{\"ok\":true}", "application/json");

                                                                                                                   } catch (const std::exception& e) {
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"invalid JSON\"}", "application/json");
                                                                                                                   }
                                                                                                                                                       });

                                                                                                               /* ----------------------------------------------------------------- */
                                                                                                               /*  /getConnectionRequest – GET – retrieve & consume a request        */
                                                                                                               svr.Get("/getConnectionRequest", [&](const httplib::Request& req,
                                                                                                                                                    httplib::Response& res) {
                                                                                                                   //std::cout << "[/getConnectionRequest] GET request received\n";

                                                                                                                   std::string target_pk = req.get_param_value("public_key");

                                                                                                                   if (target_pk.empty()) {
                                                                                                                       res.status = 400;
                                                                                                                       res.set_content("{\"error\":\"missing public_key param\"}",
                                                                                                                                       "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   auto opt_req = connStore.consume(target_pk);
                                                                                                                   if (!opt_req.has_value()) {
                                                                                                                       res.status = 404;
                                                                                                                       res.set_content("{\"error\":\"no pending request\"}",
                                                                                                                                       "application/json");
                                                                                                                       return;
                                                                                                                   }

                                                                                                                   json body = { {"requester_public_key", opt_req.value()} };
                                                                                                                   res.set_content(body.dump(), "application/json");

                                                                                                                                                    });


                                                                                                               svr.listen("217.154.48.36", 8080);

                                                                                                               return 0;
                                                                                                           }
