chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "parsePEM",
    title: "Parse PEM Data",
    contexts: ["selection"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "parsePEM") {
    chrome.windows.getAll({ populate: true }, (windows) => {
      let popupFound = windows.find(w =>
        w.type === "popup" &&
        w.tabs &&
        w.tabs[0].url &&
        w.tabs[0].url.includes("popup.html")
      );
      if (popupFound) {
        chrome.runtime.sendMessage({ action: "parsePEMData", pemData: info.selectionText });
      } else {
        chrome.windows.create(
          {
            url: chrome.runtime.getURL("popup.html"),
            type: "popup",
            width: 400,
            height: 600
          },
          () => {
            setTimeout(() => {
              chrome.runtime.sendMessage({ action: "parsePEMData", pemData: info.selectionText });
            }, 2000);
          }
        );
      }
    });
  }
});

chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    if (request.action === "parsePEMDataBackground") {
      const pemData = request.pemData;
      chrome.runtime.sendMessage({ action: "parsePEMData", pemData: pemData });
    }
  }
);