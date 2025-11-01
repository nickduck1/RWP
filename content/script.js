// Dragging logic
function makeDraggable(windowId, titleId) {
  const win = document.getElementById(windowId);
  const title = document.getElementById(titleId);
  let offsetX = 0, offsetY = 0, isDragging = false;

  title.addEventListener('mousedown', (e) => {
    isDragging = true;
    offsetX = e.clientX - win.offsetLeft;
    offsetY = e.clientY - win.offsetTop;
  });

  document.addEventListener('mousemove', (e) => {
    if (isDragging) {
      win.style.left = (e.clientX - offsetX) + 'px';
      win.style.top = (e.clientY - offsetY) + 'px';
    }
  });

  document.addEventListener('mouseup', () => {
    isDragging = false;
  });
}
makeDraggable('window1', 'titlebar1');

// Buttons
function sayHello() {
  const name = document.getElementById("nameInput").value || "stranger";
  document.getElementById("output").innerText = "Hello, " + name + "!";
}
function changeBG() {
  document.body.style.backgroundColor = "#99ccff";
}
function resetBG() {
  document.body.style.backgroundColor = "#c0c0c0";
}
function closeWindow(id) {
  document.getElementById(id).style.display = "none";
}
function showAlert() {
  alert("This is a retro alert box!");
}
function startLoading() {
  let progress = 0;
  const bar = document.getElementById("progressBar");
  bar.style.width = "0%";
  const interval = setInterval(() => {
    progress += 5;
    bar.style.width = progress + "%";
    if (progress >= 100) {
      clearInterval(interval);
      alert("Loading complete!");
    }
  }, 100);
}
function showTime() {
  const now = new Date();
  document.getElementById("output").innerText = "Current time: " + now.toLocaleTimeString();
}
function sendTestPost() {
  fetch("echo.php", {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      message: "Hello from retro UI!",
      time: new Date().toISOString()
    })
  })
  .then(res => res.json())
  .then(data => {
    document.getElementById("output").innerText =
      "Server response:\n" + JSON.stringify(data, null, 2);
  })
  .catch(err => {
    document.getElementById("output").innerText = "Error: " + err;
  });
}
