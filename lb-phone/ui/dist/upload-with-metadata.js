window.addEventListener("message", async (event) => {
  const data = event.data;
  if (data.action === "execute_upload") {
    const { uploadId, url, headers, bodyBase64 } = data;

    try {
      const byteString = atob(bodyBase64);
      const byteArray = new Uint8Array(byteString.length);
      for (let i = 0; i < byteString.length; i++) {
        byteArray[i] = byteString.charCodeAt(i);
      }
      const blob = new Blob([byteArray]);

      const response = await fetch(url, {
        method: "PUT",
        body: blob,
        headers: headers,
      });

      if (!response.ok)
        throw new Error("Upload failed: " + response.statusText);

      fetch(`https://${GetParentResourceName()}/upload_finished`, {
        method: "POST",
        body: JSON.stringify({
          uploadId: uploadId,
          success: true,
          error: null,
        }),
      });
    } catch (error) {
      console.error("Upload Error:", error);
      fetch(`https://${GetParentResourceName()}/upload_finished`, {
        method: "POST",
        body: JSON.stringify({
          uploadId: uploadId,
          success: false,
          error: error.message,
        }),
      });
    }
  }
});
