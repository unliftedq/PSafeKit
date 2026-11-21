// Synthetic interoperability fixture driver. Build and link against Password Safe's core/os.
#include "core/ItemAtt.h"
#include "core/ItemData.h"
#include "core/PWScore.h"
#include "core/PWSfileV3.h"
#include "core/PWSfileV4.h"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using pws_os::CUUID;

const StringX passphrase = L"Interop-fictitious-\u00e9-\u6d4b";
const StringX secondPassphrase = L"Interop-second-fictitious";
const StringX newPassphrase = L"Interop-replacement-fictitious";
const CUUID baseID(L"0123456789ab4cde8f0123456789abcd");
const CUUID aliasID(L"1123456789ab4cde8f0123456789abcd");
const CUUID shortcutID(L"2123456789ab4cde8f0123456789abcd");
const CUUID attachmentID(L"3123456789ab4cde8f0123456789abcd");
const CUUID shortcutBaseID(L"4123456789ab4cde8f0123456789abcd");
const unsigned char content[] = {0, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

void require(bool valid, const char *message) {
  if (!valid) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

void uuid(PWSfile &file, unsigned char type, const CUUID &id) {
  require(file.WriteField(type, *id.GetARep(), 16) > 0, "write UUID");
}

void end(PWSfile &file) {
  require(file.WriteField(0xff, nullptr, 0) > 0, "write end");
}

void writeFixture(const StringX &path, bool v4) {
  std::unique_ptr<PWSfile> file;
  if (v4) {
    PWSfileV4 seed(path + L".seed", PWSfile::Write, PWSfile::V40);
    require(seed.Open(passphrase) == PWSfile::SUCCESS, "seed key block");
    auto blocks = seed.GetKeyBlocks();
    require(seed.Close() == PWSfile::SUCCESS, "close seed");
    require(blocks.AddKeyBlock(passphrase, secondPassphrase), "add second recipient");
    auto writer = std::make_unique<PWSfileV4>(path, PWSfile::Write, PWSfile::V40);
    writer->SetKeyBlocks(blocks);
    file = std::move(writer);
  } else {
    file = std::make_unique<PWSfileV3>(path, PWSfile::Write, PWSfile::V30);
  }
  PWSfileHeader header;
  header.m_DB_Name = L"Fictitious database";
  header.m_DB_Description = L"\u6d4b\u8bd5 metadata";
  file->SetHeader(header);
  file->SetEmptyGroups({L"Unused.A", L"Unused.B"});
  UnknownFieldList unknown;
  unknown.emplace_back(0xdf, sizeof(content), content);
  file->SetUnknownHeaderFields(unknown);
  require(file->Open(passphrase) == PWSfile::SUCCESS, "open writer");

  uuid(*file, 1, baseID);
  file->WriteField(3, StringX(L"Base \u6d4b\u8bd5"));
  file->WriteField(6, StringX(L"synthetic-password"));
  file->WriteField(0x1b, content, sizeof(content));
  file->WriteField(0xe1, content, sizeof(content));
  if (v4) {
    uuid(*file, 0x1a, attachmentID);
  } else {
    file->WriteField(0x25, StringX(L"Inline title"));
    file->WriteField(0x26, StringX(L"application/octet-stream"));
    file->WriteField(0x27, StringX(L"synthetic.bin"));
    file->WriteField(0x29, content, sizeof(content));
  }
  end(*file);

  uuid(*file, 1, shortcutBaseID);
  file->WriteField(3, StringX(L"Shortcut base"));
  file->WriteField(6, StringX(L"shortcut-password"));
  end(*file);

  for (bool alias : {true, false}) {
    uuid(*file, v4 ? (alias ? 0x42 : 0x43) : 1, alias ? aliasID : shortcutID);
    file->WriteField(3, StringX(alias ? L"Alias" : L"Shortcut"));
    if (v4) {
      uuid(*file, 0x41, alias ? baseID : shortcutBaseID);
    } else {
      const StringX base = alias ? baseID : shortcutBaseID;
      file->WriteField(6, alias ? L"[[" + base + L"]]" : L"[~" + base + L"~]");
    }
    end(*file);
  }
  if (v4) {
    CItemAtt attachment;
    attachment.SetUUID(attachmentID);
    attachment.SetTitle(L"Independent title");
    attachment.SetFileName(L"synthetic.bin");
    attachment.SetMediaType(L"application/octet-stream");
    attachment.SetContent(content, sizeof(content));
    require(static_cast<PWSfileV4 &>(*file).WriteRecord(attachment) == PWSfile::SUCCESS, "write attachment");
  }
  require(file->Close() == PWSfile::SUCCESS, "close writer");
}

void readFixture(const StringX &path, bool v4, const StringX &password, bool changed, bool fresh) {
  PWScore core;
  require(core.ReadFile(path, password) == PWScore::SUCCESS, "read and authenticate fixture");
  require(core.GetReadFileVersion() == (v4 ? PWSfile::V40 : PWSfile::V30), "verify format");
  require(core.GetHeader().m_DB_Name == (changed ? L"Edited by Swift" : L"Fictitious database"), "verify database name");
  require(core.GetEmptyGroups().size() == (fresh ? 0 : 2), "verify empty groups");
  bool gotBase = false, gotAlias = false, gotShortcut = false;
  for (auto cursor = core.GetEntryIter(); cursor != core.GetEntryEndIter(); ++cursor) {
    const auto &entry = core.GetEntry(cursor);
    if (entry.GetUUID() == baseID) {
      gotBase = true;
      require(entry.GetPassword() == L"synthetic-password", "verify base password");
      if (v4) {
        require((fresh || entry.GetAttUUID() == attachmentID) && core.HasAtt(entry.GetAttUUID()), "verify attachment link");
        const auto &attachment = core.GetAtt(entry.GetAttUUID());
        require(attachment.GetFileName() == L"synthetic.bin", "verify attachment filename");
        std::vector<unsigned char> bytes(attachment.GetContentSize());
        require(attachment.GetContentLength() == sizeof(content) && attachment.GetContent(bytes.data(), bytes.size()) &&
                std::equal(std::begin(content), std::end(content), bytes.begin()), "verify independent attachment bytes");
      } else {
        const auto bytes = entry.GetAttContent();
        require(bytes.size() == sizeof(content) && std::equal(std::begin(content), std::end(content), bytes.begin()),
                "verify inline attachment");
      }
    }
    if (entry.GetUUID() == aliasID) {
      gotAlias = entry.IsAlias() && entry.GetBaseUUID() == baseID &&
                 entry.GetGroup() == (changed ? L"Edited alias" : L"");
    }
    if (entry.GetUUID() == shortcutID) gotShortcut = entry.IsShortcut() && entry.GetBaseUUID() == shortcutBaseID;
  }
  require(gotBase && (fresh || (gotAlias && gotShortcut)), "verify UUIDs and dependencies");
}

int main(int argc, char **argv) {
  require(argc == 4, "upstream-fixture write|read|read-new|read-second|read-old-rejected v3|v4 <ASCII path>");
  const std::string operation(argv[1]);
  const bool v4 = std::string(argv[2]) == "v4";
  const std::string path(argv[3]);
  const StringX file(path.begin(), path.end());
  if (operation == "write") {
    writeFixture(file, v4);
  } else if (operation == "read-old-rejected") {
    PWScore core;
    require(core.ReadFile(file, passphrase) != PWScore::SUCCESS, "old passphrase unexpectedly accepted");
  } else {
    readFixture(file, v4, operation == "read-new" ? newPassphrase :
                          operation == "read-second" ? secondPassphrase : passphrase,
                operation != "read", operation == "read-fresh");
  }
}
