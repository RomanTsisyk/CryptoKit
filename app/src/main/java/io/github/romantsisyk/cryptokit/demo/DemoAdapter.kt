package io.github.romantsisyk.cryptokit.demo

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.recyclerview.widget.RecyclerView
import io.github.romantsisyk.cryptokit.demo.databinding.ItemDemoBinding

class DemoAdapter(private val items: List<DemoItem>) :
    RecyclerView.Adapter<DemoAdapter.ViewHolder>() {

    class ViewHolder(val binding: ItemDemoBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemDemoBinding.inflate(
            LayoutInflater.from(parent.context), parent, false
        )
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val item = items[position]
        holder.binding.tvTitle.text = item.title
        holder.binding.tvDescription.text = item.description
        holder.binding.btnRun.setOnClickListener { view ->
            holder.binding.btnRun.isEnabled = false
            Thread {
                try {
                    val result = item.action()
                    view.post {
                        holder.binding.tvResult.text = result
                        holder.binding.tvResult.visibility = View.VISIBLE
                        holder.binding.btnRun.isEnabled = true
                    }
                } catch (e: Exception) {
                    view.post {
                        holder.binding.tvResult.text = "Error: ${e.message}"
                        holder.binding.tvResult.visibility = View.VISIBLE
                        holder.binding.btnRun.isEnabled = true
                    }
                }
            }.start()
        }
    }

    override fun getItemCount(): Int = items.size
}
