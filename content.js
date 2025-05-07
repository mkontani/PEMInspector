chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    if (request.action === "getSelectedText") {
      const selectedText = window.getSelection().toString();
      chrome.runtime.sendMessage({ action: "parsePEMDataBackground", pemData: selectedText });
    }
  }
);