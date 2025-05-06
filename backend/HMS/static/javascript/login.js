const sign_in_btn = document.querySelector("#sign-in-btn");
const sign_up_btn = document.querySelector("#sign-up-btn");
const container = document.querySelector(".container");

sign_up_btn.addEventListener("click", () => {
  container.classList.add("sign-up-mode");
});

sign_in_btn.addEventListener("click", () => {
  container.classList.remove("sign-up-mode");
});

document.addEventListener("DOMContentLoaded", function () {
    const signInForm = document.querySelector(".sign-in-form");
    const signUpForm = document.querySelector(".sign-up-form");
  
    function showError(input, message) {
      const inputField = input.parentElement;
      inputField.classList.add("error");
      const errorMessage = inputField.querySelector(".error-message");
      if (!errorMessage) {
        const small = document.createElement("small");
        small.classList.add("error-message");
        small.style.color = "red";
        small.innerText = message;
        inputField.appendChild(small);
      } else {
        errorMessage.innerText = message;
      }
    }
  
    function removeError(input) {
      const inputField = input.parentElement;
      inputField.classList.remove("error");
      const errorMessage = inputField.querySelector(".error-message");
      if (errorMessage) {
        errorMessage.remove();
      }
    }
  
    function isValidEmail(email) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
    }
  
    signInForm.addEventListener("submit", function (e) {
      e.preventDefault();
  
      const username = signInForm.querySelector("input[type='text']");
      const password = signInForm.querySelector("input[type='password']");
      let isValid = true;
  
      if (username.value.trim() === "") {
        showError(username, "Username is required");
        isValid = false;
      } else {
        removeError(username);
      }
  
      if (password.value.trim().length < 6) {
        showError(password, "Password must be at least 6 characters");
        isValid = false;
      } else {
        removeError(password);
      }
  
      if (isValid) {
        alert("Sign In Successful!");
        signInForm.submit();
      }
    });
  
    signUpForm.addEventListener("submit", function (e) {
      e.preventDefault();
  
      const username = signUpForm.querySelector("input[type='text']");
      const email = signUpForm.querySelector("input[type='email']");
      const password = signUpForm.querySelector("input[type='password']");
      let isValid = true;
  
      if (username.value.trim().length < 3) {
        showError(username, "Username must be at least 3 characters");
        isValid = false;
      } else {
        removeError(username);
      }
  
      if (!isValidEmail(email.value.trim())) {
        showError(email, "Enter a valid email address");
        isValid = false;
      } else {
        removeError(email);
      }
  
      if (password.value.trim().length < 6) {
        showError(password, "Password must be at least 6 characters");
        isValid = false;
      } else {
        removeError(password);
      }
  
      if (isValid) {
        alert("Sign Up Successful!");
        signUpForm.submit();
      }
    });
});