const searchForm = document.querySelector(".search-form");
const cartItem = document.querySelector(".cart-items-container");
const navbar = document.querySelector(".navbar");

const searchBtn = document.querySelector("#search-btn");
const cartBtn = document.querySelector("#cart-btn");
const menuBtn = document.querySelector("#menu-btn");


let cart = [];
const cartCount = document.querySelector("#cart-count");
const cartItemsList = document.querySelector("#cart-items-list");
const emptyCartMessage = document.querySelector("#empty-cart-message");
const cartTotal = document.querySelector("#cart-total");
const totalPrice = document.querySelector("#total-price");
const checkoutBtn = document.querySelector("#checkout-btn");

searchBtn.addEventListener("click" , function(){

    searchForm.classList.toggle("active");
    document.addEventListener("click" , function(e){
        if(
            !e.composedPath().includes(searchBtn) && !e.composedPath().includes(searchForm)){
                searchForm.classList.remove("active");
        }
    });
});
cartBtn.addEventListener("click" , function(){

    cartItem.classList.toggle("active");
    document.addEventListener("click" , function(e){
        if(
            !e.composedPath().includes(cartBtn) && !e.composedPath().includes(cartItem)){
                cartItem.classList.remove("active");
        }
    });
});
menuBtn.addEventListener("click" , function(){

    navbar.classList.toggle("active");
    document.addEventListener("click" , function(e){
        if(
            !e.composedPath().includes(menuBtn) && !e.composedPath().includes(navbar)){
                navbar.classList.remove("active");
        }
    });
});


function updateCartCount() {
    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartCount.textContent = totalItems;
    
    
    if (totalItems > 0) {
        cartCount.style.display = 'flex';
    } else {
        cartCount.style.display = 'none';
    }
}


function calculateTotal() {
    const total = cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);
    return total.toFixed(2);
}


function renderCart() {
    
    cartItemsList.innerHTML = '';
    
    if (cart.length === 0) {
        
        cartItemsList.innerHTML = `
            <div class="empty-cart" id="empty-cart-message">
                <i class="fas fa-shopping-cart" style="font-size: 5rem; color: #ccc; margin-bottom: 1rem;"></i>
                <p style="font-size: 1.8rem; color: #666;">Sepetiniz boş</p>
            </div>
        `;
        cartTotal.style.display = 'none';
        checkoutBtn.style.display = 'none';
    } else {
        
        cart.forEach((item, index) => {
            const cartItemDiv = document.createElement('div');
            cartItemDiv.className = 'cart-item';
            cartItemDiv.innerHTML = `
                <i class="fas fa-times" onclick="removeFromCart(${index})"></i>
                <img src="${item.image}" alt="${item.name}"/>
                <div class="content">
                    <h3>${item.name}</h3>
                    <div class="price">${item.price}₺ x ${item.quantity}</div>
                    <div class="quantity-controls" style="display: flex; align-items: center; gap: 1rem; margin-top: 0.5rem;">
                        <button onclick="decreaseQuantity(${index})" style="background: #ec5808; color: white; border: none; width: 2.5rem; height: 2.5rem; border-radius: 0.5rem; cursor: pointer; font-size: 1.5rem;">-</button>
                        <span style="font-size: 1.6rem; font-weight: bold;">${item.quantity}</span>
                        <button onclick="increaseQuantity(${index})" style="background: #ec5808; color: white; border: none; width: 2.5rem; height: 2.5rem; border-radius: 0.5rem; cursor: pointer; font-size: 1.5rem;">+</button>
                    </div>
                </div>
            `;
            cartItemsList.appendChild(cartItemDiv);
        });
        
        
        cartTotal.style.display = 'block';
        totalPrice.textContent = calculateTotal() + '₺';
        checkoutBtn.style.display = 'inline-block';
    }
    
    updateCartCount();
}


function addToCart(name, price, image) {
    
    const existingItem = cart.find(item => item.name === name);
    
    if (existingItem) {
        
        existingItem.quantity++;
    } else {
        
        cart.push({
            name: name,
            price: parseFloat(price),
            image: image,
            quantity: 1
        });
    }
    
    renderCart();
    
    
    cartItem.classList.add("active");
    
    
    showNotification(`${name} sepete eklendi! 🛒`);
}


function removeFromCart(index) {
    cart.splice(index, 1);
    renderCart();
    showNotification('Ürün sepetten çıkarıldı');
}


function increaseQuantity(index) {
    cart[index].quantity++;
    renderCart();
}


function decreaseQuantity(index) {
    if (cart[index].quantity > 1) {
        cart[index].quantity--;
        renderCart();
    } else {
        removeFromCart(index);
    }
}


function showNotification(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 10rem;
        right: 2rem;
        background: #4CAF50;
        color: white;
        padding: 1.5rem 2.5rem;
        border-radius: 0.5rem;
        font-size: 1.6rem;
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 2000);
}


document.addEventListener('DOMContentLoaded', function() {
    console.log(' Script yüklendi');
    
    const addToCartButtons = document.querySelectorAll('.add-to-cart');
    console.log(' Bulunan buton sayısı:', addToCartButtons.length);
    
    addToCartButtons.forEach((button, index) => {
        console.log(` Buton ${index + 1} bulundu:`, button.getAttribute('data-name'));
        
        button.addEventListener('click', function() {
            console.log(' Butona tıklandı!');
            
            const name = this.getAttribute('data-name');
            const price = this.getAttribute('data-price');
            const image = this.getAttribute('data-image');
            
            console.log(' Ürün bilgileri:', { name, price, image });
            
            addToCart(name, price, image);
        });
    });
    
    
    console.log(' Sepet render ediliyor...');
    renderCart();
    console.log('Sepet hazır!');
});


const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);