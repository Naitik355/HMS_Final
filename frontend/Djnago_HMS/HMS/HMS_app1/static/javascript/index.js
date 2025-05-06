document.addEventListener("DOMContentLoaded", function () {
    const wrapper = document.querySelector('.carousel-wrapper');
    const cards = document.querySelectorAll('.card');
    const prevBtn = document.querySelector('.prev');
    const nextBtn = document.querySelector('.next');

    const firstClone = cards[0].cloneNode(true);
    const lastClone = cards[cards.length - 1].cloneNode(true);

    wrapper.appendChild(firstClone);
    wrapper.insertBefore(lastClone, cards[0]);

    const allCards = document.querySelectorAll('.carousel-wrapper .card');
    let index = 1;

    wrapper.style.transform = `translateX(-${index * 280}px)`;

    function updateCarousel() {
        wrapper.style.transition = "transform 0.4s ease-in-out";
        wrapper.style.transform = `translateX(-${index * 280}px)`;
    }

    nextBtn.addEventListener('click', () => {
        if (index >= allCards.length - 1) return;
        index++;
        updateCarousel();
    });

    prevBtn.addEventListener('click', () => {
        if (index <= 0) return;
        index--;
        updateCarousel();
    });

    wrapper.addEventListener('transitionend', () => {
        if (index === allCards.length - 1) {
            wrapper.style.transition = "none";
            index = 1;
            wrapper.style.transform = `translateX(-${index * 280}px)`;
        }
        if (index === 0) {
            wrapper.style.transition = "none";
            index = allCards.length - 2;
            wrapper.style.transform = `translateX(-${index * 280}px)`;
        }
    });
});
document.addEventListener("DOMContentLoaded", function () {
    const today = new Date().toISOString().split("T")[0];
    console.log("Today is:", today); // Debug

    const checkin = document.getElementById("checkin");
    const checkout = document.getElementById("checkout");

    if (checkin) {
      checkin.setAttribute("min", today);
      console.log("Set min for checkin:", checkin.min);
    }

    if (checkout) {
      checkout.setAttribute("min", today);
      console.log("Set min for checkout:", checkout.min);
    }
  });