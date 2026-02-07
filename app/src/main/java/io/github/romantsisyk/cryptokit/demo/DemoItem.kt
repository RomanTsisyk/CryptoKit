package io.github.romantsisyk.cryptokit.demo

data class DemoItem(
    val title: String,
    val description: String,
    val action: () -> String
)
